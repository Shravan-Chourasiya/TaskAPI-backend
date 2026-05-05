import mongoose from "mongoose";
import type { OtpType } from "../../Types/mongo_models/otp.type.js";

export const otpSchema = new mongoose.Schema(
	{
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Users",
			required: [true, "User ID is required"],
			index: true,
		},

		email: {
			type: String,
			required: [true, "Email is required"],
			lowercase: true,
			trim: true,
			index: true,
		},

		phone: {
			type: String,
			trim: true,
			index: true,
		},



		otpHash: {
			type: String,
			required: true,
			select: false,
		},

		purpose: {
			type: String,
			enum: [
				"emailVerification",
				"emailChange",
				"phoneVerification",
				"passwordReset",
				"accountRecovery",
				"twoFactorAuth",
			],
			required: [true, "Purpose is required"],
		},

		otpStatus: {
			type: String,
			enum: ["pending", "verified", "expired", "failed"],
			default: "pending",
			index: true,
		},

		isUsed: {
			type: Boolean,
			default: false,
			index: true,
		},
		



		usedAt: Date,

		attemptsLeft: {
			type: Number,
			default: 5,
			min: 0,
		},

		failedAttempts: {
			type: Number,
			default: 0,
		},

		lastAttemptAt: Date,



		expiresAt: {
			type: Date,
			required: true,
		},
	
	},
	{
		timestamps: true,
		collection: "otps",
	},
);

const OtpModel = mongoose.model<OtpType>("OTPs", otpSchema);

export default OtpModel;
