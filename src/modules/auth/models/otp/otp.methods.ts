// ============ INSTANCE METHODS ============

import { otpSchema } from "./otp.schema.js";

/**
 * Verify provided OTP against stored hash.
 * Decrements attempts on failure, marks as verified on success.
 * @param {string} providedOtp - OTP provided by user
 * @returns {Promise<boolean>} True if OTP matches and is valid
 */
otpSchema.methods.verify = async function (
	providedOtp: string,
): Promise<boolean> {
	// Check if OTP is valid
	if (!this.isValid) {
		this.status = this.isExpired ? "expired" : "failed";
		await this.save();
		return false;
	}

	// Check if OTP matches
	const match = providedOtp === this.otp;

	if (!match) {
		this.attemptsLeft -= 1;
		this.failedAttempts += 1;
		this.lastAttemptAt = new Date();

		// Mark as failed if no attempts left
		if (this.attemptsLeft <= 0) {
			this.status = "failed";
		}

		await this.save();
		return false;
	}

	// OTP verified successfully
	this.isUsed = true;
	this.status = "verified";
	this.usedAt = new Date();
	await this.save();
	return true;
};

/**
 * Record a failed OTP verification attempt.
 * Increments failed attempts counter and updates last attempt timestamp.
 */
otpSchema.methods.recordFailedAttempt = async function (
): Promise<void> {
	this.attemptsLeft -= 1;
	this.failedAttempts += 1;
	this.lastAttemptAt = new Date();


	if (this.attemptsLeft <= 0) {
		this.status = "failed";
	}

	await this.save();
};

/**
 * Check if OTP verification is rate limited.
 * Blocks verification if 3+ failed attempts within 1 minute window.
 * @returns {boolean} True if rate limited
 */
otpSchema.methods.isRateLimited = function (): boolean {
	if (!this.lastAttemptAt) return false;

	const timeSinceLastAttempt =
		new Date().getTime() - this.lastAttemptAt.getTime();
	const rateLimitWindow = 60 * 1000; // 1 minute

	return timeSinceLastAttempt < rateLimitWindow && this.failedAttempts >= 3;
};

// ============ STATIC METHODS ============
/**
 * Find a valid (pending, unused, not expired) OTP for a user.
 * @param {string} userId - User ID
 * @param {string} purpose - OTP purpose
 * @returns {Promise} Valid OTP document or null
 */
otpSchema.statics.findValidOTP = function (userId: string, purpose: string) {
	return this.findOne({
		userId,
		purpose,
		status: "pending",
		isUsed: false,
		expiresAt: { $gt: new Date() },
	});
};

/**
 * Find a valid OTP by email address.
 * @param {string} email - Email address
 * @param {string} purpose - OTP purpose
 * @returns {Promise} Valid OTP document or null
 */
otpSchema.statics.findValidOTPByEmail = function (
	email: string,
	purpose: string,
) {
	return this.findOne({
		email: email.toLowerCase(),
		purpose,
		status: "pending",
		isUsed: false,
		expiresAt: { $gt: new Date() },
	});
};

/**
 * Invalidate all previous pending OTPs for a user and purpose.
 * Ensures only 1 valid OTP exists per purpose at any time.
 * @param {string} userId - User ID
 * @param {string} purpose - OTP purpose
 */
otpSchema.statics.invalidatePreviousOTPs = async function (
	userId: string,
	purpose: string,
): Promise<void> {
	await this.updateMany(
		{
			userId,
			purpose,
			status: "pending",
			isUsed: false,
		},
		{
			status: "expired",
			isUsed: true,
		},
	);
};

/**
 * Get OTP statistics for a user.
 * @param {string} userId - User ID
 * @returns {Promise<Object>} Statistics object with total, verified, failed, expired counts
 */
otpSchema.statics.getStatistics = async function (userId: string) {
	const [total, verified, failed, expired] = await Promise.all([
		this.countDocuments({ userId }),
		this.countDocuments({ userId, status: "verified" }),
		this.countDocuments({ userId, status: "failed" }),
		this.countDocuments({ userId, status: "expired" }),
	]);

	return { total, verified, failed, expired };
};

/**
 * Clean up expired and failed OTPs from database.
 * Complements TTL index for manual cleanup if needed.
 * @returns {Promise<number>} Number of deleted documents
 */
otpSchema.statics.cleanupExpiredOTPs = async function (): Promise<number> {
	const result = await this.deleteMany({
		expiresAt: { $lt: new Date() },
		status: { $in: ["expired", "failed"] },
	});

	return result.deletedCount || 0;
};
