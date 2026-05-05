import mongoose from "mongoose";
import type { SessionType, SessionStaticMethods, SessionInstanceMethods } from "../../Types/mongo_models/session.type.js";

export const sessionSchema = new mongoose.Schema(
	{
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Users",
			required: [true, "User ID is required"],
			index: true,
		},

		deviceId: {
			type: String,
			required: [true, "Device ID is required"],
			index: true,
		},

		deviceInfo: {
			userAgent: String,
			deviceType: {
				type: String,
				enum: ["mobile", "tablet", "desktop"],
			},
			browser: String,
			os: String,
		},

		ipAddress: {
			type: String,
			required: [true, "IP address is required"],
		},

		ipCountry: String,

		ipRegion: String,

		ipCity: String,

		// ============ TOKEN HASHES (Audit Trail Only) ============
		accessTokenHash: {
			type: String,
			required: [true, "Access token is required"],
			select: false,
		},
		refreshTokenHash: {
			type: String,
			required: [true, "Refresh token is required"],
			select: false,
		},
		/**
		 * Token family ID for detecting token theft attacks.
		 * Generated on every token refresh. If mismatch detected between
		 * user's refresh token family and latest session family = token theft.
		 * Strategy: "lose 1, lose all" - revoke all sessions when theft detected.
		 */
		tokenFamily: {
			type: String,
			index: true,
		},

		status: {
			type: String,
			enum: ["active", "revoked", "expired"],
			default: "active",
		},

		isRevoked: {
			type: Boolean,
			default: false,
			index: true,
		},

		revokedAt: Date,
		
		lastActivityAt: {
			type: Date,
			default: () => new Date(),
			index: true,
		},

		accessTokenExpiresAt: {
			type: Date,
			required: true,
		},

		refreshTokenExpiresAt: {
			type: Date,
			required: true
		},
		
	},
	{
		timestamps: true,
		collection: "sessions",
	},
);

// Import methods to attach to schema
import "./session.methods.js";
import "./session.indexes.virtual.middleware.js";

const sessionModel = mongoose.model<SessionType, SessionStaticMethods>(
	"Sessions",
	sessionSchema,
);

export default sessionModel;
