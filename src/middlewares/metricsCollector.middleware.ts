import { type Request, type Response, type NextFunction, type RequestHandler } from "express";
import type { RawEventModel, StatusClass } from "../modules/metrics/types/rawEvent.type.js";
import { METRICS_CONSTANTS } from "../constants.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toStatusClass(code: number): StatusClass {
	if (code < 300) return "2xx";
	if (code < 400) return "3xx";
	if (code < 500) return "4xx";
	return "5xx";
}

// Full request path, including the router mount prefix (baseUrl).
//
// req.route.path is only the sub-path defined on the router (e.g. "/:id"),
// and req.path / baseUrl alone fragment the metric across endpoints that live
// on the same router. So we compose baseUrl + req.route.path to get the true
// route pattern (e.g. "/client/tasks/:id") — not the concrete URL, so
// per-endpoint grouping is stable. Falls back to the concrete URL when the
// request never matched a route (404 / middleware-only paths).
function resolveRoute(req: Request): string {
	const routePath = req.route?.path as string | undefined;
	if (routePath) return (req.baseUrl + routePath) || req.originalUrl || "unknown";
	return req.originalUrl || "unknown";
}

// ─── Augmented request type ───────────────────────────────────────────────────
// apikeyhandler.middleware attaches these after successful key validation.
// Optional to stay assignable to Express RequestHandler; both recording paths
// guard on their presence, and recordEvent re-narrows them to `string`.
type MetricsRequest = Request & {
	apiKeyId?:   string;
	apiOwnerId?: string;
	_reqStartAt?: [number, number]; // process.hrtime() tuple
};

// Shape shared by the finish and close handlers.
type EventBuilderInput = {
	req: MetricsRequest;
	statusClass: StatusClass;
	errorCode?: string;
	httpStatusCode?: number;
};

// res.locals is typed Record<string, any> — narrow to a plain string so the
// value can be passed to the `error` field under exactOptionalPropertyTypes.
function readErrorCode(res: Response): string | undefined {
	const code = res.locals.errorCode as unknown;
	return typeof code === "string" ? code : undefined;
}

// ─── Factory ──────────────────────────────────────────────────────────────────
// Returns an Express middleware that hooks res.on("finish") and res.on("close")
// to write one raw event document per terminated request that has a resolved
// apiKeyId.
//
// Requests that never pass API key auth (apiKeyId absent) are skipped —
// they are already rejected by apikeyhandler before reaching controllers.
//
// Two termination paths:
//   - "finish"  — normal completion (or error response). Reads the error label
//                 that the error handler stamped onto res.locals.errorCode and
//                 writes it into the raw event's `error` field.
//   - "close"   — fires after finish AND when the client cancels the request
//                 mid-flight. A guard flag distinguishes the two: if close
//                 fires while finish never did, the request was aborted and is
//                 recorded with statusClass "aborted" (no HTTP status exists).
export function createMetricsMiddleware(rawEventModel: RawEventModel): RequestHandler {
	return function metricsMiddleware(
		req: MetricsRequest,
		res: Response,
		next: NextFunction,
	): void {
		// Capture start time as high-resolution tuple before any async work.
		req._reqStartAt = process.hrtime();

		// Fire-and-forget — never block the response.
		const recordEvent = (event: EventBuilderInput): void => {
			// Belt-and-suspenders guard; both callers already check this.
			if (!req.apiKeyId || !req.apiOwnerId) return;

			const hrDiff   = process.hrtime(req._reqStartAt);
			const durationMs = Math.round(hrDiff[0] * 1_000 + hrDiff[1] / 1_000_000);

			const rawUserAgent = req.headers["user-agent"];

			rawEventModel
				.create({
					timestamp:      new Date(),
					apiKeyId:       req.apiKeyId,
					ownerId:        req.apiOwnerId,
					route:          resolveRoute(req),
					method:         req.method,
					// Aborted requests have no HTTP status code.
					...(event.httpStatusCode !== undefined && { httpStatusCode: event.httpStatusCode }),
					statusClass:    event.statusClass,
					durationMs,
					...(event.errorCode && { error: event.errorCode }),
					...(rawUserAgent && { userAgent: rawUserAgent.substring(0, METRICS_CONSTANTS.USER_AGENT_MAX_LENGTH) }),
					...(req.ip       && { ip: req.ip }),
				})
				.catch((err: unknown) => {
					// Structured visibility on write failure. Never blocks or
					// fails the user-facing response — this is fire-and-forget.
					// TODO: replace with winston/pino once a logging util exists.
					const e = err as { message?: string; stack?: string };
					console.error(JSON.stringify({
						source: "metricsCollector",
						event: "raw_event_write_failed",
						apiKeyId: req.apiKeyId,
						ownerId: req.apiOwnerId,
						route: resolveRoute(req),
						method: req.method,
						statusClass: event.statusClass,
						durationMs,
						error: event.errorCode ?? null,
						errMessage: e.message,
						errStack: e.stack,
						timestamp: new Date().toISOString(),
					}));
				});
		};

		// True once "finish" fires — lets the close listener tell an aborted
		// request (close without finish) from a normal completion.
		let finished = false;

		res.on("finish", () => {
			// Only record events for authenticated API key requests.
			if (!req.apiKeyId || !req.apiOwnerId) return;

			finished = true;

			const statusCode = res.statusCode;
			const errorCode = readErrorCode(res);

			recordEvent({
				req,
				statusClass: toStatusClass(statusCode),
				httpStatusCode: statusCode,
				// Conditional spread — never assign undefined to an optional prop
				// (exactOptionalPropertyTypes).
				...(errorCode && { errorCode }),
			});
		});

		res.on("close", () => {
			// If finish already ran, this close is just the normal teardown —
			// the event was already recorded there.
			if (finished) return;
			// Only record events for authenticated API key requests.
			if (!req.apiKeyId || !req.apiOwnerId) return;

			// Client cancelled the request mid-flight; no response was sent.
			recordEvent({
				req,
				statusClass: "aborted",
			});
		});

		next();
	};
}
