import mongoose from "mongoose";
import { METRICS_CONSTANTS } from "../../../constants.js";
import type {
	RawAdminEventDocument,
	RawAdminEventModel,
} from "./adminEvent.type.js";

// Admin events are stored separately from api_raw_events because that backing
// collection is a Mongo time-series with metaField "apiKeyId" — every document
// requires an API key, which admin (JWT) traffic never has. Mixing them in would
// both fail the timeseries meta requirement and pollute every rollup / metric
// query that scans raw events site-wide. So admin actions get their own regular
// collection with its own 90-day TTL.
const adminEventSchema = new mongoose.Schema<RawAdminEventDocument>(
	{
		timestamp: { type: Date, required: true },
		adminId: { type: String, required: true }, // userId of the acting admin
		role: {
			type: String,
			required: true,
			enum: ["admin", "moderator"],
		},
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
			enum: ["2xx", "3xx", "4xx", "5xx", "aborted"],
		},
		durationMs: { type: Number, required: true, min: 0 },
		ip: { type: String },
		error: {
			type: String,
			maxlength: METRICS_CONSTANTS.ERROR_LABEL_MAX_LENGTH,
		},
	},
	{
		timestamps: false,
		collection: "api_admin_events",
	},
);

// Query patterns: audit logs by admin + time-range, security events by status.
adminEventSchema.index({ timestamp: -1 });
adminEventSchema.index({ adminId: 1, timestamp: -1 });
adminEventSchema.index({ route: 1, timestamp: -1 });
adminEventSchema.index(
	{ timestamp: 1 },
	{ expireAfterSeconds: METRICS_CONSTANTS.RAW_EVENT_TTL_SECONDS },
);

export function initAdminEventModel(db: mongoose.Connection) {
	return db.model<RawAdminEventDocument, RawAdminEventModel>(
		"AdminEvent",
		adminEventSchema,
	);
}