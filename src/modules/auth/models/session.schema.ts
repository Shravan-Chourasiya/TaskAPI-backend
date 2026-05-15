import mongoose from "mongoose";
import type {
	SessionType,
	SessionStaticMethods,
} from "../../../Types/mongo_models/session.type.js";

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

		userAgent: {
			type: String,
			required: [true, "User agent is required"],
		},

		ipAddress: {
			type: String,
			required: [true, "IP address is required"],
		},

		ipCountry: {
			type: String,
		},

		ipRegion: {
			type: String,
		},

		ipCity: {
			type: String,
		},

		// ============ TOKEN HASHES (Audit Trail Only) ============
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

		refreshTokenExpiresAt: {
			type: Date,
			required: true,
		},
	},
	{
		timestamps: true,
		collection: "sessions",
	},
);

// ============ INDEXES ============
sessionSchema.index({ userId: 1, deviceId: 1 });
sessionSchema.index({ userId: 1, tokenFamily: 1 });
sessionSchema.index({ deviceId: 1, isRevoked: 1 });
sessionSchema.index({ userId: 1, deviceId: 1, isRevoked: 1 });
sessionSchema.index({ userId: 1, lastActivityAt: 1 });

// TTL Index for expired refresh tokens
sessionSchema.index(
	{ refreshTokenExpiresAt: 1 },
	{
		expireAfterSeconds: 0,
		partialFilterExpression: { status: "expired" },
	},
);
sessionSchema.index(
	{ accessTokenExpiresAt: 1 },
	{
		expireAfterSeconds: 0,
		partialFilterExpression: { status: "expired" },
	},
);

// ============ VIRTUAL FIELDS ============
sessionSchema.virtual("isExpired").get(function () {
	return new Date() > this.refreshTokenExpiresAt;
});

sessionSchema.virtual("isActive").get(function () {
	return (
		this.status === "active" &&
		!this.isRevoked &&
		new Date() < this.refreshTokenExpiresAt
	);
});

// ============ INSTANCE METHODS ============

/**
 * Revoke a session and mark it as revoked.
 * @param {string} [reason] - Optional reason for revocation
 */
sessionSchema.methods.revoke = async function (reason?: string): Promise<void> {
	this.isRevoked = true;
	this.status = "revoked";
	this.revokedAt = new Date();
	this.revocationReason = reason;
	await this.save();
};

/**
 * Update last activity timestamp for the session.
 */
sessionSchema.methods.updateActivity = async function (): Promise<void> {
	this.lastActivityAt = new Date();
	await this.save();
};

/**
 * Check if session is valid (active, not revoked, and not expired).
 * @returns {boolean} True if session is valid
 */
sessionSchema.methods.isValid = function (): boolean {
	return (
		this.status === "active" &&
		!this.isRevoked &&
		new Date() < this.refreshTokenExpiresAt
	);
};

// ============ STATIC METHODS ============

/**
 * Find all active sessions for a user.
 * @param {string} userId - User ID
 * @returns {Promise} Active sessions
 */
sessionSchema.statics.findActiveSessions = function (userId: string) {
	return this.find({
		userId,
		status: "active",
		isRevoked: false,
	});
};

/**
 * Revoke all sessions for a user ("lose 1, lose all" strategy).
 * Used when token theft is detected via tokenFamily mismatch.
 * @param {string} userId - User ID
 * @param {string} [reason] - Optional reason for revocation
 */
sessionSchema.statics.revokeAllUserSessions = async function (
	userId: string,
	reason?: string,
): Promise<void> {
	await this.updateMany(
		{ userId, isRevoked: false },
		{
			isRevoked: true,
			status: "revoked",
			revokedAt: new Date(),
			revocationReason: reason,
		},
	);
};

/**
 * Find all sessions with a specific token family.
 * Used to detect and revoke sessions when token theft is suspected.
 * @param {string} tokenFamily - Token family ID
 * @returns {Promise} Sessions with matching token family
 */
sessionSchema.statics.findByTokenFamily = function (tokenFamily: string) {
	return this.find({ tokenFamily });
};

/**
 * Count active sessions for a user.
 * @param {string} userId - User ID
 * @returns {Promise<number>} Number of active sessions
 */
sessionSchema.statics.countActiveSessions = function (userId: string) {
	return this.countDocuments({
		userId,
		status: "active",
		isRevoked: false,
	});
};

const sessionModel = mongoose.model<SessionType, SessionStaticMethods>(
	"Sessions",
	sessionSchema,
);

export default sessionModel;
