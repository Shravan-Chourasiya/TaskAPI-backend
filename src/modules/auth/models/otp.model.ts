import mongoose from "mongoose";
import type { OTPModel } from "../types/dbmodel.interface.js";

const otpSchema = new mongoose.Schema(
	{
		otp: {
			type: String,
			required: [true, "OTP is required!"],
		},
		email: {
			type: String,
			required: [true, "Email is Required!"],
		},
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Users",
			required: [true, "UserID is required!"],
		},
		purpose: {
			type: String,
			enum: [
				"verifyEmailOR",
				"verifyEmailUP",
				"resetPassword",
				"account_recovery",
			],
			required: true,
		},
		fieldToUpdateNewValue: {
			type: String,
		},
		isTemp: {
			type: Boolean,
			default: false,
		},
		isUsed: {
			type: Boolean,
			default: false,
		},
		attemptsLeft: {
			type: Number,
			default: 5,
		},
		expiryTime: {
			type: Date,
			default: () => new Date(Date.now() + 10 * 60 * 1000), // 10 mins
		},
	},
	{
		timestamps: true,
	},
);

otpSchema.index({ userId: 1 }); // speeds up queries by userId
otpSchema.index({ email: 1 }); // optional, if you often query by email
otpSchema.index({ expiryTime: 1 }, { expireAfterSeconds: 0 }); // TTL cleanup

export const OtpModel = mongoose.model<OTPModel>("OTPs", otpSchema);
