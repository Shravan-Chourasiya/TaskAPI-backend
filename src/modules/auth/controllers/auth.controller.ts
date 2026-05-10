import jwt, { type JwtPayload } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { config } from "../../../configs/app.config.js";
import { generateOTP, getOtpHTML } from "../../../utils/email.utils.js";
import { sendVerificationEmail } from "../../../services/nodemailer.service.js";
import type { NextFunction, Request, Response } from "express";
import { emailPurposeMapper } from "../utils/authcontroller.utils.js";
import * as z from "zod";
import crypto from "crypto";
import type {
	otpResendSchema,
	loginDeleteRecoverAccSchema,
	otpSchema,
	registerSchema,
	usernameSchema,
	updateDetailsSchema,
	profileSchema,
} from "../../../libs/zod/auth.zodschema.js";
import userModel from "../models/users/user.schema.js";
import { otpService } from "../../../services/redisotp.service.js";
import sessionModel from "../models/session/session.schema.js";

export async function registerController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const { username, email, password }: z.infer<typeof registerSchema> =
		req.body;
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();

		const existingUser = await userModel.findOne(
			{ email, isVerified: true },
			{ session: Session },
		);
		if (existingUser) {
			return res
				.status(409)
				.json({ message: "Email Already In Use.Go to Login" });
		}
		const existingUnverifiedUser = await userModel.findOne(
			{
				email,
				isVerified: false,
			},
			{ session: Session },
		);

		if (existingUnverifiedUser) {
			const emailSubject = emailPurposeMapper("verifyEmailOR");
			const otp = generateOTP();
			const html = getOtpHTML(otp, "resend_otp");

			const mailSuccess = await sendVerificationEmail(
				config.GMAIL_USER_EMAIL,
				existingUnverifiedUser.email,
				emailSubject,
				html,
			);
			if (!mailSuccess) {
				return res.status(503).json({
					message: "Failed to send OTP email. Please try again later.",
				});
			}

			const otpStoreSuccess = await otpService.storeOTP(
				email,
				otp,
				"verifyEmailOR",
				existingUnverifiedUser._id.toString(),
			);

			if (!otpStoreSuccess.success) {
				return res.status(503).json({
					message: "Failed to store OTP. Please try again later.",
				});
			}
			return res.status(409).json({
				message:
					"Email Already Registered but not verified! Verification OTP sent to your email . Verify Email and complete registration!",
			});
		}

		const user = await userModel.create(
			[
				{
					username,
					email,
					passwordHash: password,
				},
			],
			{ session: Session },
		);
		if (!user) {
			return res.status(503).json({
				message: "User Not Registered.Please try again Later!",
			});
		}
		const otp = generateOTP();
		const html = getOtpHTML(otp, "verifyEmailOR");
		const mailSuccess = await sendVerificationEmail(
			config.GMAIL_USER_EMAIL as string,
			email,
			emailPurposeMapper("verifyEmailOR"),
			html,
		);
		if (!mailSuccess) {
			return res.status(503).json({
				message:
					"Failed to send verification email. Please try registering again later.",
			});
		}
		const otpStoreSuccess = await otpService.storeOTP(
			email,
			otp,
			"verifyEmailOR",
			user[0]?._id.toString(),
		);
		if (!otpStoreSuccess.success) {
			return res.status(503).json({
				message:
					otpStoreSuccess.message ||
					"Failed to store OTP. Please try again later.",
			});
		}

		await Session.commitTransaction();

		return res.status(201).json({
			message:
				"User Registered Successfully! Verification OTP sent to your email . Verify Email and complete registration!",
		});
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function loginController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> =
		req.body;
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();
		if (req.cookies.acToken) {
			return res.status(400).json({
				message:
					"Already Logged In! Please Logout from current session to login again!",
			});
		}

		const isUser = await userModel
			.findOne({ email }, { session: Session })
			.select("+passwordHash");
		if (!isUser) {
			return res.status(404).json({ message: "User Not Found!" });
		}

		const isPasswordCorrect = await isUser.comparePassword(password);
		if (!isPasswordCorrect) {
			await isUser.incrementFailedLogin();
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}

		if (!isUser.isVerified) {
			await isUser.incrementFailedLogin();
			return res.status(403).json({
				message:
					"Email Not Verified! Verification OTP sent to your email . Verify Email and complete registration!",
			});
		}

		if (isUser.isDeleted) {
			await isUser.incrementFailedLogin();
			return res.status(403).json({
				message:
					"Account Scheduled for Deletion! Complete Account Recovery Procedure to recover your account!",
			});
		}

		// Generate consistent deviceId from user agent
		const deviceId = crypto
			.createHash("sha256")
			.update(req.headers["user-agent"] || "unknown")
			.digest("hex");

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

		const accessToken = jwt.sign(
			{ id: isUser._id, type: "access" },
			config.ACCESS_TOKEN_JWT_SECRET,
			{ expiresIn: "10m" },
		);

		const rfTokenHash = await bcrypt.hash(refreshToken, 12);
		// Check if session exists for this device
		const existingSession = await sessionModel.findOne(
			{
				userId: isUser._id.toString(),
				deviceId: deviceId,
			},
			{ session: Session },
		);

		if (existingSession) {
			await existingSession.updateOne(
				{
					refreshTokenHash: rfTokenHash,
					tokenFamily,
					isRevoked: false,
					status: "active",
					lastActivityAt: new Date(),
					refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
				},
				{ session: Session },
			);
		} else {
			const activeSessionCount = await sessionModel.countDocuments(
				{
					userId: isUser._id.toString(),
					isRevoked: false,
				},
				{ session: Session },
			);

			if (activeSessionCount >= 5) {
				return res.status(403).json({
					message:
						"Maximum 5 devices allowed. Logout from another device first.",
				});
			}

			const newSession = await sessionModel.create(
				[
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
						isRevoked: false,
						status: "active",
						lastActivityAt: new Date(),
						refreshTokenExpiresAt: new Date(
							Date.now() + 7 * 24 * 60 * 60 * 1000,
						),
					},
				],
				{ session: Session },
			);

			if (!newSession) {
				return res.status(503).json({
					message: "Failed to create session. Please try again later.",
				});
			}
		}
		await isUser.resetFailedLogin();
		await isUser.updateLoginActivity(
			req.ip as string,
			req.headers["user-agent"] || "unknown",
		);
		await isUser.save({ session: Session });

		await Session.commitTransaction();

		res.cookie("rfToken", refreshToken, config.REFRESH_TOKEN_COOKIE_CONFIG);
		res.cookie("acToken", accessToken, config.ACCESS_TOKEN_COOKIE_CONFIG);
		return res.status(200).json({
			message: "User Logged in successfully!",
			data: {
				username: isUser.username,
				email: isUser.email,
			},
		});
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function tokenRotationController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();
		const rfToken = req.cookies.rfToken;
		if (!rfToken) {
			return res.status(400).json({
				message: "Refresh Token Not Found !",
			});
		}
		const rfTokenDecoded = jwt.verify(
			rfToken,
			config.REFRESH_TOKEN_JWT_SECRET,
		) as JwtPayload;

		if (!rfTokenDecoded || rfTokenDecoded.type !== "refresh") {
			return res.status(400).json({
				message: "Invalid Refresh Token !",
			});
		}

		const session = await sessionModel
			.findOne(
				{
					userId: rfTokenDecoded.id,
					deviceId: rfTokenDecoded.deviceId,
					tokenFamily: rfTokenDecoded.tokenFamily,
					isRevoked: false,
				},
				{ session: Session },
			)
			.select("+refreshTokenHash");

		if (!session) {
			return res.status(400).json({
				message: "Refresh token is invalid or revoked",
			});
		}
		const isRfTokenCorrect = await bcrypt.compare(
			rfToken,
			session.refreshTokenHash,
		);
		if (!isRfTokenCorrect) {
			return res.status(400).json({
				message: "Refresh token is invalid ! Login to get a new one.",
			});
		}
		const user = await userModel.findOne(
			{ _id: rfTokenDecoded.id },
			{ session: Session },
		);

		if (!user) {
			return res.status(422).json({
				message: "Error Occured in User Validation !",
			});
		}

		const tokenFamily = crypto.randomBytes(16).toString("hex");

		const acToken = jwt.sign(
			{ id: user._id, type: "access" },
			config.ACCESS_TOKEN_JWT_SECRET,
			{ expiresIn: "10m" },
		);
		const newRfToken = jwt.sign(
			{
				id: user._id,
				tokenFamily,
				deviceId: session.deviceId,
				type: "refresh",
			},
			config.REFRESH_TOKEN_JWT_SECRET,
			{
				expiresIn: "7d",
			},
		);
		const now = new Date();
		const sevenDaysfromNow = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
		const newRfTokenHash = await bcrypt.hash(newRfToken, 12);
		await session.updateOne(
			{
				refreshTokenHash: newRfTokenHash,
				isRevoked: false,
				tokenFamily,
				refreshTokenExpiresAt: sevenDaysfromNow,
				lastActivityAt: now,
			},
			{ session: Session },
		);

		await Session.commitTransaction();
		res.cookie("rfToken", newRfToken, config.REFRESH_TOKEN_COOKIE_CONFIG);
		res.cookie("acToken", acToken, config.ACCESS_TOKEN_COOKIE_CONFIG);
		res.status(200).json({
			message: "AccessToken Refreshed Successfully !",
		});
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function logoutController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();

		const rfToken = req.cookies.rfToken;
		if (!rfToken) {
			return res.status(400).json({
				message: "Refresh Token Not Found !",
			});
		}
		const rfTokenDecoded = jwt.verify(
			rfToken,
			config.REFRESH_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const session = await sessionModel
			.findOne(
				{
					userId: rfTokenDecoded.id,
					isRevoked: false,
				},
				{ session: Session },
			)
			.select("+refreshTokenHash");
		if (!session) {
			return res.status(400).json({
				message: "Refresh token is invalid or revoked | Session not found",
			});
		}
		const isRfTokenCorrect = await bcrypt.compare(
			rfToken,
			session.refreshTokenHash,
		);
		if (!isRfTokenCorrect) {
			return res.status(400).json({
				message: "Refresh token is invalid or revoked",
			});
		}
		await session.updateOne({ isRevoked: true }, { session: Session });

		await Session.commitTransaction();
		res.clearCookie("rfToken", config.REFRESH_TOKEN_COOKIE_CONFIG);
		res.clearCookie("acToken", config.ACCESS_TOKEN_COOKIE_CONFIG);
		res.status(200).json({
			message: "User Logged Out Successfully !",
		});
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function updateDetailsController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();
		const {
			fieldToUpdate,
			newValue,
			password,
		}: z.infer<typeof updateDetailsSchema> = req.body;
		const decodedToken = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const user = await userModel.findOne(
			{ _id: decodedToken.userId },
			{ session: Session },
		);
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const isPasswordCorrect = await user.comparePassword(password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}
		switch (fieldToUpdate) {
			case "username":
				await user.updateOne(
					{
						username: newValue as z.infer<typeof usernameSchema>,
					},
					{ session: Session },
				);
				await Session.commitTransaction();
				break;
			case "profile":
				await user.updateOne(
					{
						profile: newValue as z.infer<typeof profileSchema>,
					},
					{ session: Session },
				);
				await Session.commitTransaction();
				break;
			case "email": {
				const otp = generateOTP();
				const html = getOtpHTML(otp, "verifyEmailUP");
				const mailSuccess = await sendVerificationEmail(
					config.GMAIL_USER_EMAIL,
					user.email,
					emailPurposeMapper("verifyEmailUP"),
					html,
				);
				if (!mailSuccess) {
					return res.status(503).json({
						message:
							"Failed to send verification email. Please try again later.",
					});
				}
				const otpStoreSuccess = await otpService.storeOTP(
					user.email,
					otp,
					"verifyEmailUP",
					newValue,
				);
				if (!otpStoreSuccess) {
					return res.status(500).json({
						message: "Failed to store OTP. Please try again later.",
					});
				}
				await Session.commitTransaction();
				break;
			}
			case "password": {
				const otp2 = generateOTP();
				const html2 = getOtpHTML(otp2, "resetPassword");

				const mailSuccess2 = await sendVerificationEmail(
					config.GMAIL_USER_EMAIL,
					user.email,
					emailPurposeMapper("resetPassword"),
					html2,
				);

				if (!mailSuccess2) {
					return res.status(503).json({
						message:
							"Failed to send verification email. Please try again later.",
					});
				}

				const newPasswordHash = await bcrypt.hash(newValue, 12);
				const otpStoreSuccess = await otpService.storeOTP(
					user.email,
					otp2,
					"resetPassword",
					newPasswordHash,
				);

				if (!otpStoreSuccess) {
					return res.status(500).json({
						message: "Failed to store OTP. Please try again later.",
					});
				}
				await Session.commitTransaction();
				break;
			}
			default:
				return res.status(400).json({ message: "Invalid Field to Update!" });
		}
		return res.status(200).json({
			message:
				"Verification OTP sent to your email! Complete OTP verification to update your details!",
		});
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function deleteAccountController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();

		const acToken = req.cookies.acToken;
		if (!acToken) {
			return res.status(400).json({
				message: "Access Token Not Found | Unauthorised !",
			});
		}
		const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> =
			req.body;
		const user = await userModel
			.findOne({ email }, { session: Session })
			.select("+passwordHash");

		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}

		const isPasswordCorrect = await user.comparePassword(password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}

		if (user.isDeleted) {
			return res
				.status(400)
				.json({ message: "Account Already Scheduled to be Deleted!" });
		}

		await user.softDelete(user._id.toString());
		await user.save({ session: Session });
		await Session.commitTransaction();
		return res.status(200).json({
			message:
				"Account Scheduled to be Deleted! To recover Your Account ,Complete Account Recovery Procedure within 30 days !",
		});
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function recoverDeletedAccountController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();
		const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> =
			req.body;
		const user = await userModel
			.findOne({ email }, { session: Session })
			.select("+passwordHash");

		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const isPasswordCorrect = await user.comparePassword(password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}
		if (!user.isDeleted) {
			return res
				.status(400)
				.json({ message: "Account is not Scheduled to be Deleted!" });
		}
		const otp = generateOTP();
		const html = getOtpHTML(otp, "account_recovery");
		const mailSuccess = await sendVerificationEmail(
			config.GMAIL_USER_EMAIL,
			user.email,
			"Account Recovery Verification on TaskAPI",
			html,
		);
		if (!mailSuccess) {
			return res.status(503).json({
				message: "Failed to send verification email. Please try again later.",
			});
		}
		const otpStoreSuccess = await otpService.storeOTP(
			email,
			otp,
			"account_recovery",
			user._id.toString(),
		);
		if (!otpStoreSuccess.success) {
			return res.status(503).json({
				message:
					otpStoreSuccess.message ||
					"Failed to store OTP. Please try again later.",
			});
		}
		await Session.commitTransaction();
		return res.status(200).json({
			message:
				"OTP Sent to your Email! Complete OTP Verification to recover your account!",
		});
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function getUserAccountController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const accessToken = req.cookies.acToken;
		const decodedToken = jwt.verify(
			accessToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const user = await userModel.findOne({ _id: decodedToken.id });

		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		if (user.isDeleted) {
			return res.status(400).json({
				message:
					"Account Scheduled for Deletion! Complete Account Recovery Procedure to recover your account!",
			});
		}
		return res.status(200).json({
			message: "User Account Details Fetched Successfully!",
			data: {
				username: user.username,
				email: user.email,
				status: user.status,
				role: user.roles,
			},
		});
	} catch (error) {
		next(error);
	}
}

export async function verificationController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();
		const { otp, email }: z.infer<typeof otpSchema> = req.body;
		if (req.query.purpose === "ve-em-or") {
			const otpResult = await otpService.verifyOTP(email, otp, "verifyEmailOR");
			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			const userId = otpResult.userId;
			if (!userId) {
				return res.status(400).json({
					message:
						"Invalid OTP verification attempt.Please try registering after some Time.",
				});
			}
			const user = await userModel.findOne(
				{ _id: userId },
				{ session: Session },
			);
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			if (user.isVerified) {
				return res.status(400).json({ message: "Email Already Verified!" });
			}
			user.isVerified = true;
			await user.save({ session: Session });
			await Session.commitTransaction();
			return res.status(200).json({
				message:
					"Email Verified Successfully! You can now login to your account!",
			});
		} else if (req.query.purpose === "ve-em-up") {
			const otpResult = await otpService.verifyOTP(email, otp, "verifyEmailUP");

			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			if (!otpResult.newValue) {
				return res
					.status(400)
					.json({ message: "New email value not found in OTP data." });
			}
			const userId = otpResult.userId;
			if (!userId) {
				return res.status(400).json({
					message:
						"Invalid OTP verification attempt.Please try registering after some Time.",
				});
			}
			const user = await userModel.findOne(
				{ _id: userId },
				{ session: Session },
			);
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			if (user.isVerified) {
				return res.status(400).json({ message: "Email Already Verified!" });
			}
			user.email = otpResult.newValue;
			user.isVerified = true;
			await user.save({ session: Session });
			await Session.commitTransaction();
			return res.status(200).json({
				message:
					"Email Updated Successfully! You can now login to your account!",
			});
		} else if (req.query.purpose === "re-pa") {
			const otpResult = await otpService.verifyOTP(email, otp, "resetPassword");

			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			if (!otpResult.newValue) {
				return res
					.status(400)
					.json({ message: "New password value not found in OTP data." });
			}
			const userId = otpResult.userId;
			if (!userId) {
				return res.status(400).json({
					message:
						"Invalid OTP verification attempt.Please try registering after some Time.",
				});
			}
			const user = await userModel.findOne(
				{ _id: userId },
				{ session: Session },
			);
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			if (user.isVerified) {
				return res.status(400).json({ message: "Email Already Verified!" });
			}
			const isSameAsOldPassword = await user.isPasswordReused(
				otpResult.newValue,
			);
			if (isSameAsOldPassword) {
				return res
					.status(400)
					.json({ message: "New Password cannot be same as last  password!" });
			}
			user.passwordHash = otpResult.newValue;
			user.isVerified = true;
			await user.save({ session: Session });
			await Session.commitTransaction();
			return res.status(200).json({
				message:
					"Password Updated Successfully! You can now login to your account!",
			});
		} else if (req.query.purpose === "ac-re") {
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				"accountRecovery",
			);

			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			if (!otpResult.newValue) {
				return res
					.status(400)
					.json({ message: "New email value not found in OTP data." });
			}
			const userId = otpResult.userId;
			if (!userId) {
				return res.status(400).json({
					message:
						"Invalid OTP verification attempt.Please try registering after some Time.",
				});
			}
			const user = await userModel.findOne(
				{ _id: userId, isDeleted: true },
				{ session: Session },
			);
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			if (user.status === "active") {
				return res
					.status(400)
					.json({ message: "Account is already recovered!" });
			}
			await user.restore();
			await user.save({ session: Session });
			await Session.commitTransaction();
			return res.status(200).json({
				message:
					"Account Recovered Successfully! You can now login to your account!",
			});
		} else {
			return res
				.status(403)
				.json({ message: "Invalid Access for Verification API!" });
		}
	} catch (error) {
		if (Session) {
			await Session.abortTransaction();
		}
		next(error);
	} finally {
		if (Session) {
			await Session.endSession();
		}
	}
}

export async function resendOtpController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const purpose = req.query.purpose;
		const { email }: z.infer<typeof otpResendSchema> = req.body;
		const user = await userModel.findOne({ email });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}

		const emailSubject = emailPurposeMapper(purpose as string);

		const otp = generateOTP();
		const html = getOtpHTML(otp, "resendOtp");

		const mailSuccess = await sendVerificationEmail(
			config.GMAIL_USER_EMAIL,
			user.email,
			emailSubject,
			html,
		);
		if (!mailSuccess) {
			return res.status(503).json({
				message: "Failed to send OTP email. Please try again later.",
			});
		}
		const otpStoreSuccess = await otpService.storeOTP(
			email,
			otp,
			"resendOtp",
			user._id.toString(),
		);
		if (!otpStoreSuccess.success) {
			return res.status(503).json({
				message:
					otpStoreSuccess.message ||
					"Failed to store OTP. Please try again later.",
			});
		}

		return res.status(200).json({
			message: "OTP resent successfully! Please check your email.",
		});
	} catch (error) {
		next(error);
	}
}
