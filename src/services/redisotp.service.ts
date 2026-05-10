// services/otp.service.ts
import bcrypt from "bcryptjs";
import { redisClient } from "../configs/redis.init.js";

interface PendingOTP {
	otpHash: string;
	email: string;
	userId: string | undefined;
	purpose: string;
	newValue: string|undefined;
	attemptsLeft: number;
	failedAttempts: number;
	createdAt: number;
	expiresAt: number;
}


export const otpService = {
	/**
	 * Store OTP in Redis
	 * @param email - User email
	 * @param otp - Plain OTP (will be hashed)
	 * @param purpose - OTP purpose
	 * @param userId - Optional user ID
	 * @param ttl - Time to live in seconds (default: 600 = 10 min)
	 */
	async storeOTP(
		email: string,
		otp: string,
		purpose: string,
		userId?: string,
		newValue?: string,
		ttl: number = 600,
	): Promise<{ success: boolean; message?: string }> {
		const otpExists = await this.otpExists(email, purpose);
		if (otpExists) {
			await this.invalidateOTP(email, purpose); // Invalidate existing OTP for the same purpose
		}
		const otpHash = await bcrypt.hash(otp, 12);
		const key = `otp:${email.toLowerCase()}:${purpose}`;
		const data: PendingOTP = {
			otpHash,
			email: email.toLowerCase(),
			userId,
			purpose,
			newValue,
			attemptsLeft: 5,
			failedAttempts: 0,
			createdAt: Date.now(),
			expiresAt: Date.now() + ttl * 1000,
		};

		// Store in Redis with TTL
		await redisClient.setex(key, ttl, JSON.stringify(data));
		console.warn(
			`OTP stored for ${email} with purpose ${purpose} (expires in ${ttl} seconds)`,
		);
		return { success: true };
	},

	/**
	 * Verify OTP from Redis
	 * @param email - User email
	 * @param otp - Plain OTP provided by user
	 * @param purpose - OTP purpose
	 * @returns Object with success status and message
	 */
	async verifyOTP(
		email: string,
		otp: string,
		purpose: string,
	): Promise<{ success: boolean; message: string; userId?: string ,newValue?: string}> {
		const key = `otp:${email.toLowerCase()}:${purpose}`;
		const data = await redisClient.get(key);

		if (!data) {
			return {
				success: false,
				message: "OTP not found or expired",
			};
		}

		const otpData: PendingOTP = JSON.parse(data);

		// Check if expired
		if (Date.now() > otpData.expiresAt) {
			await redisClient.del(key);
			return {
				success: false,
				message: "OTP expired",
			};
		}

		// Check if rate limited (3+ failed attempts in last minute)
		if (otpData.failedAttempts >= 3) {
			const timeSinceCreation = Date.now() - otpData.createdAt;
			if (timeSinceCreation < 60000) {
				return {
					success: false,
					message: "Too many failed attempts. Please try again later.",
				};
			}
		}

		// Check attempts left
		if (otpData.attemptsLeft <= 0) {
			await redisClient.del(key);
			return {
				success: false,
				message: "Maximum attempts exceeded",
			};
		}

		// Verify OTP
		const isValid = await bcrypt.compare(otp, otpData.otpHash);

		if (!isValid) {
			// Decrement attempts and update
			otpData.attemptsLeft -= 1;
			otpData.failedAttempts += 1;

			if (otpData.attemptsLeft <= 0) {
				await redisClient.del(key);
				return {
					success: false,
					message: "Invalid OTP. Maximum attempts exceeded.",
				};
			}

			// Update Redis with new attempt count
			const remainingTTL = Math.floor((otpData.expiresAt - Date.now()) / 1000);
			await redisClient.setex(key, remainingTTL, JSON.stringify(otpData));

			return {
				success: false,
				message: `Invalid OTP. ${otpData.attemptsLeft} attempts remaining.`,
			};
		}
		const otpNewValue = otpData.newValue?.toString() || "";
		// OTP verified successfully - delete from Redis
		await redisClient.del(key);

		return otpData.userId
			? {
				success: true,
				message: "OTP verified successfully",
				userId: otpData.userId,
				newValue: otpNewValue,
			}
			: {
				success: true,
				message: "OTP verified successfully",
				newValue: otpNewValue,
			};
	},

	/**
	 * Check if OTP exists for email and purpose
	 */
	async otpExists(email: string, purpose: string): Promise<boolean> {
		const key = `otp:${email.toLowerCase()}:${purpose}`;
		const exists = await redisClient.exists(key);
		return exists === 1;
	},

	/**
	 * Get remaining attempts for OTP
	 */
	async getRemainingAttempts(
		email: string,
		purpose: string,
	): Promise<number | null> {
		const key = `otp:${email.toLowerCase()}:${purpose}`;
		const data = await redisClient.get(key);

		if (!data) {return null};
        
		const otpData: PendingOTP = JSON.parse(data);
		return otpData.attemptsLeft;
	},

	/**
	 * Invalidate OTP (delete from Redis)
	 */
	async invalidateOTP(email: string, purpose: string): Promise<void> {
		const key = `otp:${email.toLowerCase()}:${purpose}`;
		await redisClient.del(key);
	},

	/**
	 * Get OTP data (for debugging or additional checks)
	 */
	async getOTPData(email: string, purpose: string): Promise<PendingOTP | null> {
		const key = `otp:${email.toLowerCase()}:${purpose}`;
		const data = await redisClient.get(key);

		if (!data){ return null};

		return JSON.parse(data);
	},
};
