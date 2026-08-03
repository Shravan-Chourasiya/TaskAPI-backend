import type { Document, Model } from "mongoose";
import type { StatusClass } from "../../metrics/types/rawEvent.type.js";

export type AdminRole = "admin" | "moderator";

// ─── Admin event document ──────────────────────────────────────────────────────
// One document = one completed request to a site-admin route, authenticated by
// the acting admin's JWT session (not an API key). Stored in a plain collection
// (api_admin_events) separate from the API-key time-series raw events.
export type RawAdminEventType = {
	timestamp: Date;          // timeField/finish wall time
	adminId:   string;        // userId of the acting admin
	role:      AdminRole;     // admin | moderator (at request time)
	route:     string;        // full path, e.g. "/api/v1/site-admin/users/get-all"
	method:    string;        // HTTP verb — GET / POST / PATCH / DELETE
	httpStatusCode: number;   // exact status code, e.g. 200, 400, 500
	statusClass: StatusClass; // bucketed class derived from httpStatusCode

	durationMs: number;       // wall-clock ms from req received to res finish

	// ── Optional enrichment ────────────────────────────────────────────────────
	ip?:    string;           // client IP
	error?: string;           // short error label for 4xx/5xx, e.g. "VALIDATION_ERROR"
};

export interface RawAdminEventDocument extends RawAdminEventType, Document {}

export interface RawAdminEventModel extends Model<RawAdminEventDocument> {}