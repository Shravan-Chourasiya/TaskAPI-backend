import mongoose from "mongoose";
import { METRICS_CONSTANTS } from "../../../constants.js";
import type {
	SecurityEventDocument,
	SecurityEventModel,
} from "./securityEvent.type.js";

// Failed-auth / security events go into their own plain collection rather than
// api_raw_events (a Mongo time-series keyed on metaField "apiKeyId") because the
// requests that produce them — missing/invalid API keys, expired JWT sessions,
// CSRF failures — have NO apiKeyId. A time-series doc requires the metaField, so
// these records cannot live there; the security-events audit route also wants a
// compact, always-writable store for purely unauthenticated traffic.
const securityEventSchema = new mongoose.Schema<SecurityEventDocument>(
	{
		timestamp: { type: Date, required: true },
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
		context: { type: String },
		apiKeyId: { type: String },
		ownerId: { type: String },
		adminId: { type: String },
		error: {
			type: String,
			maxlength: METRICS_CONSTANTS.ERROR_LABEL_MAX_LENGTH,
		},
		ip: { type: String },
	},
	{
		timestamps: false,
		collection: "api_security_events",
	},
);

// Query patterns: security-events dashboard by status + window, grouped by route
// and error; TTL keeps the collection bounded (mirrors the raw-event retention).
securityEventSchema.index({ timestamp: -1 });
securityEventSchema.index({ httpStatusCode: 1, timestamp: -1 });
securityEventSchema.index({ route: 1, timestamp: -1 });
securityEventSchema.index(
	{ timestamp: 1 },
	{ expireAfterSeconds: METRICS_CONSTANTS.RAW_EVENT_TTL_SECONDS },
);

export function initSecurityEventModel(db: mongoose.Connection) {
	return db.model<SecurityEventDocument, SecurityEventModel>(
		"SecurityEvent",
		securityEventSchema,
	);
}
