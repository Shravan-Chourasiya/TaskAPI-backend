// ============ INSTANCE METHODS ============

import { sessionSchema } from "./session.schema.js";

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

// Update activity
/**
 * Update last activity timestamp for the session.
 */
sessionSchema.methods.updateActivity = async function (): Promise<void> {
	this.lastActivityAt = new Date();
	await this.save();
};

// Check if session is valid
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
