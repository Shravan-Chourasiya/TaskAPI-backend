import mongoose from "mongoose";
import type {
	RawEventDocument,
	RawEventModel,
} from "../types/rawEvent.type.js";
import { METRICS_CONSTANTS } from "../../../constants.js";

// ─── TTL ──────────────────────────────────────────────────────────────────────
// Raw events are high-volume; retain for 90 days then let MongoDB purge them.
// Rollup buckets (Phase 3+) carry the long-term history.
const { RAW_EVENT_TTL_SECONDS, USER_AGENT_MAX_LENGTH, ERROR_LABEL_MAX_LENGTH } =
	METRICS_CONSTANTS;

// ─── Schema ───────────────────────────────────────────────────────────────────
// NOTE: For a time-series collection the schema is applied to the backing
// system.buckets collection, not declared via timeseries option here.
// We define it as a regular schema and pass timeseries options in
// initRawEventModel so Mongoose creates the collection correctly.
const rawEventSchema = new mongoose.Schema<RawEventDocument>(
	{
		// ── Time-series fields ────────────────────────────────────────────────
		timestamp: { type: Date, required: true },
		apiKeyId: { type: String, required: true }, // metaField

		// ── Dimensions ───────────────────────────────────────────────────────
		ownerId: { type: String, required: true },
		route: { type: String, required: true },
		method: {
			type: String,
			required: true,
			enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
		},
		httpStatusCode: { type: Number, required: true },
		statusClass: {
			type: String,
			required: true,
			enum: ["2xx", "3xx", "4xx", "5xx"],
		},

		// ── Measure ──────────────────────────────────────────────────────────
		durationMs: { type: Number, required: true, min: 0 },

		// ── Optional enrichment ──────────────────────────────────────────────
		userAgent: { type: String, maxlength: USER_AGENT_MAX_LENGTH },
		ip: { type: String },
		error: { type: String, maxlength: ERROR_LABEL_MAX_LENGTH },
	},
	{
		// No _id auto-generation overhead — time-series collections manage
		// their own internal _id on the bucket documents.
		// _id: false,
		// Disable Mongoose timestamps; we manage `timestamp` explicitly.
		timestamps: false,
		collection: "api_raw_events",
	},
);

// ─── Indexes ──────────────────────────────────────────────────────────────────
// Time-series collections in MongoDB manage the primary time+meta index
// internally. We add secondary indexes for the query patterns in Phase 7.

// Pattern: "show me all events for this key in a time range"
rawEventSchema.index({ apiKeyId: 1, timestamp: -1 });

// Pattern: "show me all errors in a time range across keys"
rawEventSchema.index({ statusClass: 1, timestamp: -1 });

// Pattern: "show me all events for this owner across all their keys"
rawEventSchema.index({ ownerId: 1, timestamp: -1 });

// TTL — MongoDB removes documents where timestamp is older than TTL_SECONDS
rawEventSchema.index(
	{ timestamp: 1 },
	{ expireAfterSeconds: RAW_EVENT_TTL_SECONDS },
);

// ─── Model factory ────────────────────────────────────────────────────────────
export function initRawEventModel(db: mongoose.Connection): RawEventModel {
	// Create the time-series collection if it does not exist yet.
	// createCollection is a no-op if the collection already exists.
	db.createCollection("api_raw_events", {
		timeseries: {
			timeField: "timestamp",
			metaField: "apiKeyId",
			granularity: "seconds",
		},
		// Mirror the TTL at the collection level (belt-and-suspenders).
		expireAfterSeconds: RAW_EVENT_TTL_SECONDS,
	}).catch((err: unknown) => {
		// Code 48 = collection already exists — safe to ignore.
		if ((err as { code?: number }).code !== 48) {
			console.error(
				"[metrics] Failed to create api_raw_events collection:",
				err,
			);
		}
	});
	
	console.log(
		"[RAWEVENTSCHEMA]: Created time-series collection api_raw_events with TTL ",
	);

	return db.model<RawEventDocument, RawEventModel>("RawEvent", rawEventSchema);
}
