import { Request, Response, NextFunction } from "express";
import type { RawEventModel, StatusClass } from "../modules/metrics/types/rawEvent.type.js";
import { METRICS_CONSTANTS } from "../constants.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toStatusClass(code: number): StatusClass {
	if (code < 300) return "2xx";
	if (code < 400) return "3xx";
	if (code < 500) return "4xx";
	return "5xx";
}

// Normalise the Express matched route pattern.
// Falls back to raw path if no route was matched (e.g. 404).
function resolveRoute(req: Request): string {
	return (req.route?.path as string | undefined) ?? req.path ?? "unknown";
}

// ─── Augmented request type ───────────────────────────────────────────────────
// apikeyhandler.middleware attaches these after successful key validation.
type MetricsRequest = Request & {
	apiKeyId?:   string;
	apiOwnerId?: string;
	_reqStartAt?: [number, number]; // process.hrtime() tuple
};

// ─── Factory ──────────────────────────────────────────────────────────────────
// Returns an Express middleware that hooks res.on("finish") to write one raw
// event document per completed request that has a resolved apiKeyId.
//
// Requests that never pass API key auth (apiKeyId absent) are skipped —
// they are already rejected by apikeyhandler before reaching controllers.
export function createMetricsMiddleware(rawEventModel: RawEventModel) {
	return function metricsMiddleware(
		req: MetricsRequest,
		res: Response,
		next: NextFunction,
	): void {
		// Capture start time as high-resolution tuple before any async work.
		req._reqStartAt = process.hrtime();

		res.on("finish", () => {
			// Only record events for authenticated API key requests.
			if (!req.apiKeyId || !req.apiOwnerId) return;

			const hrDiff   = process.hrtime(req._reqStartAt);
			const durationMs = Math.round(hrDiff[0] * 1_000 + hrDiff[1] / 1_000_000);
			const statusCode = res.statusCode;

			const rawUserAgent = req.headers["user-agent"];

			// Fire-and-forget — never block the response.
			rawEventModel.create({
				timestamp:      new Date(),
				apiKeyId:       req.apiKeyId,
				ownerId:        req.apiOwnerId,
				route:          resolveRoute(req),
				method:         req.method,
				httpStatusCode: statusCode,
				statusClass:    toStatusClass(statusCode),
				durationMs,
				...(rawUserAgent && { userAgent: rawUserAgent.substring(0, METRICS_CONSTANTS.USER_AGENT_MAX_LENGTH) }),
				...(req.ip       && { ip: req.ip }),
			}).catch((err: unknown) => {
				// Log but never crash the server over a metrics write failure.
				console.error("[metrics] Failed to write raw event:", err);
			});
		});

		next();
	};
}
