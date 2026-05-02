// ============ INSTANCE METHODS ============

import { sessionSchema } from "./session.model.js";

// Revoke session
sessionSchema.methods.revoke = async function (reason?: string): Promise<void> {
	this.isRevoked = true;
	this.status = "revoked";
	this.revokedAt = new Date();
	await this.save();
};

// Update activity
sessionSchema.methods.updateActivity = async function (): Promise<void> {
	this.lastActivityAt = new Date();
	await this.save();
};

// Check if session is valid
sessionSchema.methods.isValid = function (): boolean {
	return (
		this.status === "active" &&
		!this.isRevoked &&
		new Date() < this.refreshTokenExpiresAt
	);
};

// ============ STATIC METHODS ============
// Find active sessions for user
sessionSchema.statics.findActiveSessions = function (userId: string) {
	return this.find({
		userId,
		status: "active",
		isRevoked: false,
	});
};

// Revoke all sessions for user
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
			
		},
	);
};

// Find session by token family (for rotation attacks)
sessionSchema.statics.findByTokenFamily = function (tokenFamily: string) {
	return this.find({ tokenFamily });
};

// Count active sessions for user
sessionSchema.statics.countActiveSessions = function (userId: string) {
	return this.countDocuments({
		userId,
		status: "active",
		isRevoked: false,
	});
};
