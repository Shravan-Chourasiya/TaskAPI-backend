import type { Document, Model } from "mongoose";

// ─── Status class ─────────────────────────────────────────────────────────────
// Derived from HTTP status code at capture time; stored explicitly so
// aggregation pipelines can filter by class without arithmetic on statusCode.
export type StatusClass = "2xx" | "3xx" | "4xx" | "5xx";

// ─── Raw event document ───────────────────────────────────────────────────────
// One document = one completed HTTP request that passed API key auth.
// Stored in a MongoDB time-series collection; `timestamp` is the timeField.
export type RawEventType = {
	// ── Time-series required ──────────────────────────────────────────────────
	timestamp: Date;           // timeField — set to request-finish wall time

	// ── Cardinality / metaField ───────────────────────────────────────────────
	// MongoDB time-series metaField; low-cardinality grouping key.
	// Stored as string (ObjectId.toString()) to keep the schema self-contained.
	apiKeyId: string;

	// ── Dimensions ────────────────────────────────────────────────────────────
	ownerId:        string;    // userId of the API key owner (for cross-key queries)
	route:          string;    // normalised Express route pattern, e.g. "/client/auth/login"
	method:         string;    // HTTP verb — GET / POST / PATCH / DELETE
	httpStatusCode: number;    // exact status code, e.g. 200, 401, 500
	statusClass:    StatusClass; // bucketed class derived from httpStatusCode

	// ── Measure ───────────────────────────────────────────────────────────────
	durationMs: number;        // wall-clock ms from req received to res finish

	// ── Optional enrichment ───────────────────────────────────────────────────
	// Populated when available; never throw if missing.
	userAgent?: string;        // truncated to 200 chars to cap document size
	ip?:        string;        // client IP (hashed/masked in production if needed)
	error?:     string;        // short error label for 4xx/5xx, e.g. "VALIDATION_ERROR"
};

export interface RawEventDocument extends RawEventType, Document {}

export interface RawEventModel extends Model<RawEventDocument> {}
