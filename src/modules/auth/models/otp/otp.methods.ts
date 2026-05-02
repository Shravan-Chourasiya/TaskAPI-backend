// ============ INSTANCE METHODS ============

import { otpSchema } from "./otp.model.js";

// Verify OTP
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

// Record failed attempt
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

// Check if rate limited
otpSchema.methods.isRateLimited = function (): boolean {
	if (!this.lastAttemptAt) return false;

	const timeSinceLastAttempt =
		new Date().getTime() - this.lastAttemptAt.getTime();
	const rateLimitWindow = 60 * 1000; // 1 minute

	return timeSinceLastAttempt < rateLimitWindow && this.failedAttempts >= 3;
};

// ============ STATIC METHODS ============
// Find valid OTP for user
otpSchema.statics.findValidOTP = function (userId: string, purpose: string) {
	return this.findOne({
		userId,
		purpose,
		status: "pending",
		isUsed: false,
		expiresAt: { $gt: new Date() },
	});
};

// Find valid OTP by email
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

// Invalidate previous OTPs for user
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

// Get OTP statistics
otpSchema.statics.getStatistics = async function (userId: string) {
	const [total, verified, failed, expired] = await Promise.all([
		this.countDocuments({ userId }),
		this.countDocuments({ userId, status: "verified" }),
		this.countDocuments({ userId, status: "failed" }),
		this.countDocuments({ userId, status: "expired" }),
	]);

	return { total, verified, failed, expired };
};

// Clean up old OTPs (manual cleanup if TTL doesn't work)
otpSchema.statics.cleanupExpiredOTPs = async function (): Promise<number> {
	const result = await this.deleteMany({
		expiresAt: { $lt: new Date() },
		status: { $in: ["expired", "failed"] },
	});

	return result.deletedCount || 0;
};
