import bcrypt from "bcryptjs";
import crypto from "crypto";
import { userSchema } from "./user.schema.js";

// ============ INSTANCE METHODS ============
// Compare password
userSchema.methods.comparePassword = async function (
	candidatePassword: string,
): Promise<boolean> {
	return bcrypt.compare(candidatePassword, this.password);
};

// Check if password was used before
userSchema.methods.isPasswordReused = async function (
	newPassword: string,
): Promise<boolean> {
	if (!this.lastPassword) return false;
	return bcrypt.compare(newPassword, this.lastPassword);
};

// Increment failed login attempts
userSchema.methods.incrementFailedLogin = async function (): Promise<void> {
	this.failedLoginAttempts += 1;
	this.lastFailedLoginAt = new Date();

	// Lock account after 5 failed attempts for 15 minutes
	if (this.failedLoginAttempts >= 5) {
		this.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
	}

	// Lock account for 1 hour after 10 attempts
	if (this.failedLoginAttempts >= 10) {
		this.accountLockedUntil = new Date(Date.now() + 60 * 60 * 1000);
	}

	// Suspend account after 15 attempts
	if (this.failedLoginAttempts >= 15) {
		this.status = "suspended";
		this.accountLockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
	}

	await this.save();
};

// Reset failed login attempts
userSchema.methods.resetFailedLogin = async function (): Promise<void> {
	this.failedLoginAttempts = 0;
	this.accountLockedUntil = undefined;
	this.lastFailedLoginAt = undefined;
	await this.save();
};

// Update login activity
userSchema.methods.updateLoginActivity = async function (
	ip: string,
	userAgent: string,
): Promise<void> {
	this.lastLoginAt = new Date();
	this.lastLoginIP = ip;
	this.lastActiveAt = new Date();
	this.loginCount += 1;
	this.activeSessions += 1;

	// Parse user agent (basic implementation)
	this.lastLoginDevice.push({
		userAgent,
		deviceType: /mobile/i.test(userAgent) ? "mobile" : "desktop",
		browser: userAgent.split("/")[0] || "unknown",
		os: /windows/i.test(userAgent)
			? "Windows"
			: /mac/i.test(userAgent)
				? "macOS"
				: /linux/i.test(userAgent)
					? "Linux"
					: "unknown",
		deviceId: crypto.randomBytes(16).toString("hex"),
	});

	await this.save();
};

// Soft delete account
userSchema.methods.softDelete = async function (
	deletedBy?: string,
): Promise<void> {
	this.isDeleted = true;
	this.deletedAt = new Date();
	this.status = "deleted";
	this.scheduledDeletionAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
	if (deletedBy) this.deletedBy = deletedBy;
	await this.save();
};

// Restore deleted account
userSchema.methods.restore = async function (): Promise<void> {
	this.isDeleted = false;
	this.deletedAt = undefined;
	this.scheduledDeletionAt = undefined;
	this.deletedBy = undefined;
	this.status = this.isVerified ? "active" : "unverified";
	await this.save();
};

// Generate verification token
userSchema.methods.generateVerificationToken = function (): string {
	const token = crypto.randomBytes(32).toString("hex");
	this.verificationToken = crypto
		.createHash("sha256")
		.update(token)
		.digest("hex");
	this.verificationTokenExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
	return token;
};

// ============ STATIC METHODS FOR ADMIN USE =============
// Find active users
userSchema.statics.findActive = function () {
	return this.find({ status: "active", isDeleted: false });
};

// Find by email (case-insensitive)
userSchema.statics.findByEmail = function (email: string) {
	return this.findOne({ email: email.toLowerCase(), isDeleted: false });
};

// Find by username (case-insensitive)
userSchema.statics.findByUsername = function (username: string) {
	return this.findOne({ username: username.toLowerCase(), isDeleted: false });
};

// Find users by role
userSchema.statics.findByRole = function (role: string) {
	return this.find({ roles: role, isDeleted: false });
};

// Get user statistics
userSchema.statics.getStatistics = async function () {
	const [total, active, unverified, suspended, deleted] = await Promise.all([
		this.countDocuments({ isDeleted: false }),
		this.countDocuments({ status: "active", isDeleted: false }),
		this.countDocuments({ status: "unverified", isDeleted: false }),
		this.countDocuments({ status: "suspended", isDeleted: false }),
		this.countDocuments({ isDeleted: true }),
	]);

	return { total, active, unverified, suspended, deleted };
};
