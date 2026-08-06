import { type Request, type Response, type NextFunction, type RequestHandler } from "express";
import type { StatusClass } from "../modules/metrics/types/rawEvent.type.js";
import type { SecurityEventModel } from "../modules/siteadmin/models/securityEvent.type.js";
import { logger } from "../utils/logger.utils.js";

// Status-class helper mirrored from metricsCollector (kept local — importing
// across feature boundaries for a two-line fn isn't worth the coupling).
function toStatusClass(code: number): StatusClass {
	if (code < 300) return "2xx";
	if (code < 400) return "3xx";
	if (code < 500) return "4xx";
	return "5xx";
}

type SecurityRequest = Request & {
	// Identity fields the auth middlewares attach on SUCCESS. When any of these
	// resolve, the request is recorded by its owning collector instead (api-key
	// raw events / admin events), so this middleware deliberately skips them to
	// avoid duplicate security records. Only fully/anonymously failing requests
	// land here — exactly the gap TODOS_CRIT P3 describes.
	apiKeyId?: string;
	userID?:   string;
	_reqStartAt?: [number, number];
};

function readErrorCode(res: Response): string | undefined {
	const code = res.locals.errorCode as unknown;
	return typeof code === "string" ? code : undefined;
}

// No error label was stamped (auth middlewares return directly without one) —
// fall back to a coarse 401/403 bucket so the security-events audit still has a
// groupable dimension. Kept tiny; the raw event for a resolved key carries the
// precise AppError code, this only covers anonymous failures.
function fallbackLabel(statusCode: number): string | undefined {
	if (statusCode === 401) return "UNAUTHORIZED";
	if (statusCode === 403) return "FORBIDDEN";
	return undefined;
}

/**
 * Records one security event per FAILED request timestops at a 401/403 that
 * resolved no actor identity — i.e. an unauthenticated/forbidden request the
 * api-key and admin collectors never saw.
 *
 * Registered globally (app-level) but inside it only writes on:
 *   - response status 401 or 403, AND
 *   - neither req.apiKeyId (valid API key) nor req.userID (valid session/admin)
 *     was attached, meaning the request died during auth before any collector
 *     with an identity guard could record it.
 *
 * Finish/close contract mirrors the other two collectors:
 *   - "finish"  — reads res.locals.errorCode if an error handler stamped it.
 *   - "close"   — fires after finish and when the client cancels mid-flight; a
 *                 close with no prior finish is recorded as "aborted".
 */
export function createSecurityMetricsMiddleware(
	securityEventModel: SecurityEventModel,
): RequestHandler {
	return function securityMetricsMiddleware(
		req: SecurityRequest,
		res: Response,
		next: NextFunction,
	): void {
		req._reqStartAt = process.hrtime();

		const recordEvent = (
			statusCode: number | undefined,
			errorCode: string | undefined,
		): void => {
			// Only failed-auth/forbidden responses with no identity are ours.
			if (statusCode !== 401 && statusCode !== 403) return;
			if (req.apiKeyId || req.userID) return;

			const hrDiff = process.hrtime(req._reqStartAt);
			const durationMs = Math.round(hrDiff[0] * 1_000 + hrDiff[1] / 1_000_000);

			securityEventModel
				.create({
					timestamp:      new Date(),
					route:          req.originalUrl || "unknown",
					method:         req.method,
					httpStatusCode: statusCode,
					statusClass:    toStatusClass(statusCode),
					durationMs,
					...(errorCode && { error: errorCode }),
					...(req.ip && { ip: req.ip }),
				})
				.catch((err: unknown) => {
					const e = err as { message?: string; stack?: string };
					logger.error("security_event_write_failed", {
						source: "securityMetricsCollector",
						event: "security_event_write_failed",
						route: req.originalUrl,
						method: req.method,
						httpStatusCode: statusCode,
						errMessage: e.message,
						errStack: e.stack,
						timestamp: new Date().toISOString(),
					});
				});
		};

		let finished = false;

		res.on("finish", () => {
			if (finished) return;
			finished = true;
			const statusCode = res.statusCode;
			const errorCode = readErrorCode(res) ?? fallbackLabel(statusCode);
			recordEvent(statusCode, errorCode);
		});

		res.on("close", () => {
			// If finish already ran, the event was recorded there. A close with
			// no prior finish means the client cancelled mid-flight — no HTTP
			// status, no auth decision yet — so nothing to record here.
			if (finished) return;
		});

		next();
	};
}