import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { AUTH_OTP_PURPOSES, APP_REDIS_PREFIXES } from "../../../constants.js";
import { config } from "../../../configs/app.config.js";
import { sendVerificationEmail } from "../../../services/nodemailer.service.js";
import { otpService } from "../../../services/redisotp.service.js";
import { generateOTP, getOtpHTML } from "../../../utils/nodemailer.utils.js";
import type { NextFunction, Request, Response } from "express";
import { Model } from "mongoose";
import {
	UserDocument,
	UserStaticMethods,
} from "../../../types/mongoModels/user.type.js";
import { SessionStaticMethods } from "../../../types/mongoModels/session.type.js";
import { generateCsrfToken } from "../../../middlewares/csrf.middleware.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import { sendCsrfResponse, standardResponse } from "../../../utils/apiResponse.utils.js";

export const OTP_PREFIX = APP_REDIS_PREFIXES.OTP_STORAGE;
export { AUTH_OTP_PURPOSES };

export type RequestWithUser = Request & {
	userID?: string;
	sessionId?: string;
	token?: string;
};

export async function sendAndStoreOTP(
	email: string,
	purpose: string,
	docId: string,
	htmlTemplate: string,
	newValue?: string,
): Promise<{ success: boolean; message?: string }> {
	const otp = generateOTP();
	const html = getOtpHTML(otp, htmlTemplate);
	const subject = emailPurposeMapper(purpose);

	const mailSent = await sendVerificationEmail(
		config.GMAIL_USER_EMAIL,
		email,
		subject,
		html,
	);
	if (!mailSent) {
		return {
			success: false,
			message: "Failed to send email. Please try again later.",
		};
	}

	return otpService.storeOTP(email, otp, purpose, docId, newValue);
}

export const emailPurposeMapper = (purpose: string): string => {
	switch (purpose) {
		case "verifyEmailOR":
		case "ve-em-or":
			return "Email Verification for New Registration on TaskAPI";
		case "verifyEmailUP":
		case "ve-em-up":
			return "Email Verification for Email Update on TaskAPI";
		case "ve-em-cu":
			return "Confirm Your Current Email - TaskAPI";
		case "resetPassword":
		case "fr-pa":
			return "Password Reset Verification for Your TaskAPI Account";
		case "up-pa":
			return "Confirm Password Change - TaskAPI";
		case "accountRecovery":
		case "ac-re":
			return "Account Recovery Verification for Your TaskAPI Account";
		case "resendOtp":
			return "OTP Verification for Your TaskAPI Account";
		case "forgotPassword":
			return "Password Reset Verification for Your TaskAPI Account";
		case "deleteAccount":
			return "Account Deletion Scheduled for Your TaskAPI Account";
		default:
			return "Email Verification";
	}
};

export const generateTOTPSecret = async (email: string) => {
	const secret = speakeasy.generateSecret({
		name: `MyApp (${email})`,
		length: 24,
	});
	if (!secret || !secret.otpauth_url) {
		return null;
	}

	try {
		const qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);
		return {
			base32: secret.base32,
			qrCodeDataURL,
		};
	} catch {
		return null; // qrcode.toDataURL can reject
	}
};

export const verifyTOTP = (secret: string, token: string) => {
	if (!secret || !token) return false;
	return speakeasy.totp.verify({
		secret,
		encoding: "base32",
		token,
		window: 1, // allow ±30s drift
	});
};

export const issueTokensAndCreateSession = async (
	req: Request,
	res: Response,
	next: NextFunction,
	sessionModel: SessionStaticMethods,
	isUser: UserDocument,
	deviceId: string,
) => {
	try {
		// Check if session exists for this device
		const existingSession = await sessionModel.findOne({
			userId: isUser._id.toString(),
			isRevoked: false,
			deviceId: deviceId,
		});

		if (existingSession) {
			const tokenFamily = crypto.randomBytes(16).toString("hex");
			const csrfToken = generateCsrfToken();

			const refreshToken = jwt.sign(
				{
					id: isUser._id,
					tokenFamily: tokenFamily,
					deviceId: deviceId,
					type: "refresh",
				},
				config.REFRESH_TOKEN_JWT_SECRET,
				{
					expiresIn: "7d",
				},
			);

			const accessToken = jwt.sign(
				{
					id: isUser._id,
					sessionId: existingSession._id.toString(),
					type: "access",
				},
				config.ACCESS_TOKEN_JWT_SECRET,
				{ expiresIn: "10m" },
			);

			const rfTokenHash = await bcrypt.hash(refreshToken, 12);
			await existingSession.updateOne({
				refreshTokenHash: rfTokenHash,
				tokenFamily,
				csrfToken,
				isRevoked: false,
				status: "active",
				lastActivityAt: new Date(),
				refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
			});
			// Don't increment activeSessions - existing session reused

			res.cookie("acToken", accessToken, {
				httpOnly: true,
				secure: true,
				sameSite: "lax",
				maxAge: 600000,
			});
			return sendCsrfResponse(req, res, csrfToken, 200, {
				success: true,
				message: "User Logged in successfully!",
				data: {
					username: isUser.username,
					profile: isUser.profile,
					status: isUser.status,
					role: isUser.role,
				},
			});
		} else {
			const deviceId = uuidv4();
			const tokenFamily = crypto.randomBytes(16).toString("hex");

			const refreshToken = jwt.sign(
				{
					id: isUser._id,
					tokenFamily: tokenFamily,
					deviceId: deviceId,
					type: "refresh",
				},
				config.REFRESH_TOKEN_JWT_SECRET,
				{
					expiresIn: "7d",
				},
			);

			const rfTokenHash = await bcrypt.hash(refreshToken, 12);
			// Check if session exists for this device
			const activeSessionCount = await sessionModel.countDocuments({
				userId: isUser._id.toString(),
				isRevoked: false,
			});

			if (activeSessionCount >= 5) {
				return res.status(403).json(standardResponse(false, "Maximum active sessions reached. Please log out from another device."));
			}
			isUser.sessionDevices.push(deviceId);
			await isUser.save();
			const csrfToken = generateCsrfToken();
			const newSession = await sessionModel.create([
				{
					userId: isUser._id.toString(),
					deviceId: deviceId,
					userAgent: req.headers["user-agent"] || "unknown",
					ipAddress: req.ip || "unknown",
					ipCountry: req.headers["cf-ipcountry"]?.toString() || "unknown",
					ipRegion: req.headers["cf-ipregion"]?.toString() || "unknown",
					ipCity: req.headers["cf-ipcity"]?.toString() || "unknown",
					tokenFamily,
					refreshTokenHash: rfTokenHash,
					csrfToken,
					isRevoked: false,
					sessionDevices: [deviceId],
					status: "active",
					lastActivityAt: new Date(),
					refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
				},
			]);

			if (!newSession) {
				return res.status(503).json({
					message: "Failed to create session. Please try again later.",
				});
			}

			const accessToken = jwt.sign(
				{
					id: isUser._id,
					sessionId: newSession[0]?._id?.toString(),
					type: "access",
				},
				config.ACCESS_TOKEN_JWT_SECRET,
				{ expiresIn: "10m" },
			);
			// Increment activeSessions only for NEW session
			isUser.activeSessions += 1;

			await isUser.resetFailedLogin();
			await isUser.updateLoginActivity(
				req.ip as string,
				req.headers["user-agent"] || "unknown",
			);
			await isUser.save();

			res.clearCookie("devid");
			res.clearCookie("tempToken");
			res.cookie("rfToken", refreshToken, {
				httpOnly: true,
				secure: true,
				sameSite: "lax",
				maxAge: 604800000,
			});
			res.cookie("acToken", accessToken, {
				httpOnly: true,
				secure: true,
				sameSite: "lax",
				maxAge: 600000,
			});
			res.cookie("devid", deviceId, {
				httpOnly: true,
				secure: true,
				sameSite: "lax",
				maxAge: 604800000 * 4,
			});
			return sendCsrfResponse(req, res, csrfToken, 200, {
				...standardResponse(true, "User Logged in successfully!", null),
				data: {
					username: isUser.username,
					email: isUser.email,
					status: isUser.status,
					role: isUser.role,
					avatarUrl: isUser.profile?.avatarUrl,
				},
			});
		}
	} catch (err: any) {
		next(err);
	}
};
