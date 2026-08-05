import type { Document, Model } from "mongoose";
import type { StatusClass } from "../../metrics/types/rawEvent.type.js";

// ─── Security event document ──────────────────────────────────────────────────
// One document = one FAILED auth or 4xx/3xx security event that reached the
// response but was never captured by the API-key metrics collector (no valid
// apiKeyId) or the admin metrics collector (no verified adminId). Stored in a
// plain collection (api_security_events) so unauthenticated requests (which
// have no apiKeyId metaField) can be recorded at all.
export type SecurityEventType = {
	timestamp: Date;        // finish wall time
	route:      string;      // full path, e.g. "/api/v1/client/auth/login"
	method:     string;      // HTTP verb
	httpStatusCode: number;  // exact status code — 401 / 403
	statusClass: StatusClass;// bucketed class derived from httpStatusCode

	durationMs: number;      // wall-clock ms from req received to res finish

	// ── Optional enrichment ────────────────────────────────────────────────────
	// Present lazily when a half-valid request resolved enough identity (e.g.
	// a valid key that later failed CSRF, or a JWT-authenticated admin hitting
	// a CSRF/authorization wall). Null for fully anonymous 401s.
	context?: string;        // coarse source: "API_KEY" | "JWT" | "ADMIN" | "ANON"
	apiKeyId?: string;       // resolved API key id when available
	ownerId?:  string;       // resolved owner id when available
	adminId?:  string;       // resolved admin userId when available
	error?:    string;       // short label — INVALID_KEY, TOKEN_EXPIRED, CSRF_* ...
	ip?:       string;       // client IP
};

export interface SecurityEventDocument extends SecurityEventType, Document {}

export interface SecurityEventModel extends Model<SecurityEventDocument> {}