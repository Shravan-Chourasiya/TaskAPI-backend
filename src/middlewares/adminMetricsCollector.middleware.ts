import { type Request, type Response, type NextFunction, type RequestHandler } from "express";
import type { StatusClass } from "../modules/metrics/types/rawEvent.type.js";
import type { RawAdminEventModel, AdminRole } from "../modules/siteadmin/models/adminEvent.type.js";

// Status-class helper mirrored from metricsCollector (kept local — importing
// across feature boundaries for a two-line fn isn't worth the coupling).
function toStatusClass(code: number): StatusClass {
	if (code < 300) return "2xx";
	if (code < 400) return "3xx";
	if (code < 500) return "4xx";
	return "5xx";
}

type AdminEventRequest = Request & {
	// siteAdminController.utils.resolveAdminUser attaches these after verifying
	// the admin session; the recordEvent guards on them before writing.
	userID?: string;
	_adminRole?: AdminRole;
	_reqStartAt?: [number, number]; // process.hrtime() tuple
};

type AdminEventInput = {
	req: AdminEventRequest;
	statusClass: StatusClass;
	httpStatusCode?: number;
	errorCode?: string;
};

function readErrorCode(res: Response): string | undefined {
	const code = res.locals.errorCode as unknown;
	return typeof code === "string" ? code : undefined;
}

/**
 * Records one admin-event document per request to a site-admin route.
 *
 * Runs as the LAST site-admin middleware (after resolveAdminUser inside the
 * controllers), so every finished request has a verified adminId + role. This
 * deliberately does NOT run globally: it is applied per-router via a wrapper
 * that bails unless resolveAdminUser succeeded, keeping non-admin traffic out
 * of api_admin_events entirely.
 *
 * Mirrors metricsCollector's finish/close contract:
 *   - "finish"  — normal completion; reads res.locals.errorCode stamped by the
 *                 error handler and persists it into the event's `error` field.
 *   - "close"   — fires after finish AND when the client cancels mid-flight; a
 *                 close without a prior finish means aborted (no HTTP status).
 */
export function createAdminMetricsMiddleware(
	adminEventModel: RawAdminEventModel,
): RequestHandler {
	return function adminMetricsMiddleware(
		req: AdminEventRequest,
		res: Response,
		next: NextFunction,
	): void {
		req._reqStartAt = process.hrtime();

		const recordEvent = (event: AdminEventInput): void => {
			// Only record requests that passed admin auth (resolveAdminUser ran).
			if (!req.userID || !req._adminRole) return;

			const hrDiff = process.hrtime(req._reqStartAt);
			const durationMs = Math.round(hrDiff[0] * 1_000 + hrDiff[1] / 1_000_000);

			adminEventModel
				.create({
					timestamp:      new Date(),
					adminId:        req.userID,
					role:           req._adminRole,
					route:          req.baseUrl + req.path || req.originalUrl || "unknown",
					method:         req.method,
					...(event.httpStatusCode !== undefined && { httpStatusCode: event.httpStatusCode }),
					statusClass:    event.statusClass,
					durationMs,
					...(event.errorCode && { error: event.errorCode }),
					...(req.ip && { ip: req.ip }),
				})
				.catch((err: unknown) => {
					// Fire-and-forget — never block or fail the admin response.
					const e = err as { message?: string; stack?: string };
					console.error(JSON.stringify({
						source: "adminMetricsCollector",
						event: "admin_event_write_failed",
						adminId: req.userID,
						route: req.baseUrl + req.path || req.originalUrl || "unknown",
						method: req.method,
						statusClass: event.statusClass,
						durationMs,
						errMessage: e.message,
						errStack: e.stack,
						timestamp: new Date().toISOString(),
					}));
				});
		};

		let finished = false;

		res.on("finish", () => {
			if (finished) return;
			finished = true;
			if (!req.userID || !req._adminRole) return;

			const statusCode = res.statusCode;
			const errorCode = readErrorCode(res);

			recordEvent({
				req,
				statusClass: toStatusClass(statusCode),
				httpStatusCode: statusCode,
				...(errorCode && { errorCode }),
			});
		});

		res.on("close", () => {
			if (finished) return;
			if (!req.userID || !req._adminRole) return;

			recordEvent({
				req,
				statusClass: "aborted",
			});
		});

		next();
	};
}
