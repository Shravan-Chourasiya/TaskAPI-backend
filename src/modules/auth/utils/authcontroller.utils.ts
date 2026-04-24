import type { NextFunction, Request, Response } from "express";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../../../configs/configs.js";
import { OtpModel } from "../models/otp.model.js";
import bcrypt from "bcryptjs";
import { userModel } from "../models/user.model.js";
import { generateOTP, getOtpHTML } from "../../../utils/email.utils.js";
import { sendVerificationEmail } from "../../../services/email.service.js";
import type { UserModel } from "../types/dbmodel.interface.js";
import type { emailSchema, passwordSchema } from "../../../libs/zodschemas.js";
import * as z from "zod";
import e from "express";

export const EmailVerificationHandler =
	(otp: string) => async (req: Request, res: Response, next: NextFunction) => {
		const decoded = jwt.verify(
			req.cookies.tempToken,
			config.JWT_SECRET,
		) as JwtPayload;
		try {
			const otpRecord = await OtpModel.findOne({
				userId: decoded.id,
				purpose: "verifyEmailOR",
				isUsed: false,
			});
			if (!otpRecord) {
				return res.status(400).json({ message: "Invalid OTP!" });
			}
			if (otpRecord.expiryTime.getTime() < Date.now()) {
				return res
					.status(400)
					.json({ message: "OTP Expired! Please request for a new one!" });
			}

			const isOtpCorrect = await bcrypt.compare(otp, otpRecord.otp);
			if (!isOtpCorrect) {
				return res.status(403).json({ message: "InCorrect OTP!" });
			}
			const user = await userModel.findOne({ _id: otpRecord.userId });
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			await user.updateOne({ isVerified: true });
			await otpRecord.updateOne({ isUsed: true });
			res.clearCookie("tempToken", config.COOKIE_CONF_TT);
			await OtpModel.deleteOne({ _id: otpRecord._id });
			return res.status(200).json({ message: "Email Verified Successfully!" });
		} catch (error) {
			next(error);
		}
	};

export const ResetPasswordHandler =
	(otp: string) => async (req: Request, res: Response, next: NextFunction) => {
		try {
			const decoded = jwt.verify(
				req.cookies.acToken,
				config.JWT_SECRET_2,
			) as JwtPayload;
			const otpRecord = await OtpModel.findOne({
				userId: decoded.id,
				purpose: "resetPassword",
				isTemp: true,
				isUsed: false,
			});
			if (!otpRecord) {
				return res.status(400).json({ message: "Invalid OTP!" });
			}
			const isOtpCorrect = await bcrypt.compare(otp, otpRecord.otp);
			if (!isOtpCorrect) {
				return res.status(400).json({ message: "Invalid OTP!" });
			}
			if (otpRecord.expiryTime.getTime() < Date.now()) {
				return res
					.status(400)
					.json({ message: "OTP Expired! Failed to reset password!" });
			}
			const user = await userModel.findOne({ _id: otpRecord.userId });

			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			await user.updateOne({
				password: otpRecord.fieldToUpdateNewValue as z.infer<
					typeof passwordSchema
				>,
			});
			await user.save();
			await otpRecord.updateOne({ isUsed: true });
			await OtpModel.deleteOne({ _id: otpRecord._id });
			return res.status(200).json({
				message: "Password Reset Successfully!",
				data: { username: user.username, email: user.email },
			});
		} catch (error) {
			next(error);
		}
	};

export const EmailUpdationHandler =
	(otp: string) => async (req: Request, res: Response, next: NextFunction) => {
		try {
			const acToken = req.cookies.acToken;
			const decoded = jwt.verify(acToken, config.JWT_SECRET_2) as JwtPayload;
			const otpRecord = await OtpModel.findOne({
				userId: decoded.id,
				purpose: "verifyEmailUP",
				isTemp: true,
				isUsed: false,
			});
			if (!otpRecord) {
				return res.status(400).json({ message: "Invalid OTP!" });
			}
			const isOtpCorrect = await bcrypt.compare(otp, otpRecord.otp);
			if (!isOtpCorrect) {
				return res.status(400).json({ message: "Invalid OTP!" });
			}
			if (otpRecord.expiryTime.getTime() < Date.now()) {
				return res
					.status(400)
					.json({ message: "OTP Expired! Email was not updated!" });
			}
			const user = await userModel.findOne(
				{ _id: otpRecord.userId },
				{ new: true },
			);
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			await user.updateOne({
				email: otpRecord.fieldToUpdateNewValue as z.infer<typeof emailSchema>,
			});
			await otpRecord.updateOne({ isUsed: true });
			await OtpModel.deleteOne({ _id: otpRecord._id });
			return res.status(200).json({
				message: "Email Updated Successfully!",
				data: { username: user.username, email: user.email },
			});
		} catch (error) {
			next(error);
		}
	};

export const AccountRecoveryHandler =
	(otp: string) => async (req: Request, res: Response, next: NextFunction) => {
		try {
			const decoded = jwt.verify(
				req.cookies.acToken,
				config.JWT_SECRET_2,
			) as JwtPayload;
			const otpRecord = await OtpModel.findOne({
				userId: decoded.id,
				purpose: "account_recovery",
				isTemp: true,
				isUsed: false,
			});
			if (!otpRecord) {
				return res.status(400).json({ message: "Invalid OTP!" });
			}
			const isOtpCorrect = await bcrypt.compare(otp, otpRecord.otp);
			if (!isOtpCorrect) {
				return res.status(400).json({ message: "Invalid OTP!" });
			}
			if (otpRecord.expiryTime.getTime() < Date.now()) {
				return res
					.status(400)
					.json({ message: "OTP Expired! Account recovery failed!" });
			}
			const user = await userModel.findOneAndUpdate(
				{ _id: otpRecord.userId },
				{ isDeleted: false },
				{ new: true },
			);
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			await user.updateOne({ isDeleted: false });
			await otpRecord.updateOne({ isUsed: true });
			await OtpModel.deleteOne({ _id: otpRecord._id });
			return res.status(200).json({
				message: "Account Recovered Successfully!",
				data: { username: user.username, email: user.email },
			});
		} catch (error) {
			next(error);
		}
	};

export const emailPurposeMapper = (purpose: string): string => {
	switch (purpose) {
		case "verifyEmailOR":
			return "Email Verification for New Registration on TaskAPI";
		case "verifyEmailUP":
			return "Email Verification for Email Update on TaskAPI";
		case "resetPassword":
			return "Password Reset Verification for Your TaskAPI Account";
		case "account_recovery":
			return "Account Recovery Verification for Your TaskAPI Account";
		case "resend_otp":
			return "OTP Verification for Your TaskAPI Account";
		default:
			return "Email Verification";
	}
};
