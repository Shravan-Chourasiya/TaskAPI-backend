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
	phoneVerificationSchema,
	profileUpdateSchema,
} from "../../../libs/zod/auth.zodschema.js";
import userModel from "../models/user.schema.js";
import { otpService } from "../../../services/redisotp.service.js";
import sessionModel from "../models/session.schema.js";
import { sendVerificationSMS } from "../../../services/twilio.service.js";
import { RequestWithFileUrl } from "../../../middlewares/fileupload.middleware.js";

export async function registerController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const { username, email, password }: z.infer<typeof registerSchema> =
		req.body;
	try {
		const existingUser = await userModel.findOne({ email, isVerified: true });
		if (existingUser) {
			return res
				.status(409)
				.json({ message: "Email Already In Use.Go to Login" });
		}
		const existingUnverifiedUser = await userModel.findOne({
			email,
			isVerified: false,
		});

		if (existingUnverifiedUser) {
			const emailSubject = emailPurposeMapper("verifyEmailOR");
			const otp = generateOTP();
			const html = getOtpHTML(otp, "resendOtp");

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
				isRegisteredButNotVerified: true,
			});
		}

		const user = await userModel.create([
			{
				username,
				email,
				passwordHash: password,
			},
		]);
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

		return res.status(201).json({
			message:
				"User Registered Successfully! Verification OTP sent to your email . Verify Email and complete registration!",
		});
	} catch (error) {
		next(error);
	}
}

export async function loginController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> =
		req.body;

	try {
		if (req.cookies.acToken) {
			return res.status(400).json({
				message:
					"Already Logged In! Please Logout from current session to login again!",
			});
		}

		const isUser = await userModel.findOne({ email }).select("+passwordHash");
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
		const existingSession = await sessionModel.findOne({
			userId: isUser._id.toString(),
			deviceId: deviceId,
		});

		if (existingSession) {
			await existingSession.updateOne({
				refreshTokenHash: rfTokenHash,
				tokenFamily,
				isRevoked: false,
				status: "active",
				lastActivityAt: new Date(),
				refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
			});
		} else {
			const activeSessionCount = await sessionModel.countDocuments({
				userId: isUser._id.toString(),
				isRevoked: false,
			});

			if (activeSessionCount >= 5) {
				return res.status(403).json({
					message:
						"Maximum 5 devices allowed. Logout from another device first.",
				});
			}

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
					isRevoked: false,
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
		}
		await isUser.resetFailedLogin();
		await isUser.updateLoginActivity(
			req.ip as string,
			req.headers["user-agent"] || "unknown",
		);
		await isUser.save();

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
		return res.status(200).json({
			message: "User Logged in successfully!",
			data: {
				username: isUser.username,
				email: isUser.email,
				status: isUser.status,
				role: isUser.roles,
				avatarUrl: isUser.profile?.avatarUrl,
			},
		});
	} catch (error) {
		next(error);
	}
}

export async function tokenRotationController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
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
			.findOne({
				userId: rfTokenDecoded.id,
				deviceId: rfTokenDecoded.deviceId,
				tokenFamily: rfTokenDecoded.tokenFamily,
				isRevoked: false,
			})
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
		const user = await userModel.findOne({ _id: rfTokenDecoded.id });

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
		await session.updateOne({
			refreshTokenHash: newRfTokenHash,
			isRevoked: false,
			tokenFamily,
			refreshTokenExpiresAt: sevenDaysfromNow,
			lastActivityAt: now,
		});

		res.cookie("rfToken", newRfToken, {
			httpOnly: true,
			secure: true,
			sameSite: "lax",
			maxAge: 604800000,
		});
		res.cookie("acToken", acToken, {
			httpOnly: true,
			secure: true,
			sameSite: "lax",
			maxAge: 600000,
		});
		res.status(200).json({
			message: "AccessToken Refreshed Successfully !",
		});
	} catch (error) {
		next(error);
	}
}

export async function logoutController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
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
			.findOne({
				userId: rfTokenDecoded.id,
				isRevoked: false,
			})
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
		await session.updateOne({ isRevoked: true });

		res.clearCookie("rfToken", {
			httpOnly: true,
			secure: true,
			sameSite: "lax",
			maxAge: 604800000,
		});
		res.clearCookie("acToken", {
			httpOnly: true,
			secure: true,
			sameSite: "lax",
			maxAge: 600000,
		});
		res.status(200).json({
			message: "User Logged Out Successfully !",
		});
	} catch (error) {
		next(error);
	}
}

export async function updateDetailsController(
	req: RequestWithFileUrl,
	res: Response,
	next: NextFunction,
) {
	try {
		const {
			fieldToUpdate,
			newValue,
			password,
		}: z.infer<typeof updateDetailsSchema> = req.body;

		const decodedToken = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const user = await userModel.findOne({ _id: decodedToken.userId });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const isPasswordCorrect = await user.comparePassword(password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}
		switch (fieldToUpdate) {
			case "username":
				await user.updateOne({
					username: newValue as z.infer<typeof usernameSchema>,
				});
				return res.status(200).json({
					message: "Username updated successfully!",
				});
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
		next(error);
	}
}

export async function updateProfile(
	req: RequestWithFileUrl,
	res: Response,
	next: NextFunction,
) {
	try {
		const { newValue }: z.infer<typeof profileUpdateSchema> =
			req.body;
		const fileUrl = req.fileUrl;

		const decodedToken = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const user = await userModel.findOne({ _id: decodedToken.id });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		// const isPasswordCorrect = await user.comparePassword(password);
		// if (!isPasswordCorrect) {
		// 	return res.status(403).json({ message: "Invalid Password.Try Again!" });
		// }
		console.warn("Received profile update request with data:", { newValue, fileUrl });
		// Merge new profile data with existing, add avatar URL if uploaded
		const profileUpdationDetails = {
			...user.profile,
			...newValue,
			...(fileUrl && { avatarUrl: fileUrl }),
		};
		if(!profileUpdationDetails) {
			return res.status(400).json({ message: "No valid profile data provided for update!" });
		}
		user.profile = profileUpdationDetails;
		await user.save();
		return res.status(200).json({
			message: "Profile updated successfully!",
			data: {
				profile: user.profile,
				avatarUrl: user.profile?.avatarUrl,
			},
		});
	} catch (error) {
		next(error);
	}
}

export async function deleteAccountController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const acToken = req.cookies.acToken;
		if (!acToken) {
			return res.status(400).json({
				message: "Access Token Not Found | Unauthorised !",
			});
		}
		const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> =
			req.body;
		const user = await userModel.findOne({ email }).select("+passwordHash");

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
		await user.save();
		return res.status(200).json({
			message:
				"Account Scheduled to be Deleted! To recover Your Account ,Complete Account Recovery Procedure within 30 days !",
		});
	} catch (error) {
		next(error);
	}
}

export async function recoverDeletedAccountController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> =
			req.body;
		const user = await userModel.findOne({ email }).select("+passwordHash");

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
		const html = getOtpHTML(otp, "accountRecovery");
		const mailSuccess = await sendVerificationEmail(
			config.GMAIL_USER_EMAIL,
			user.email,
			emailPurposeMapper("accountRecovery"),
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
			"accountRecovery",
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
			message:
				"OTP Sent to your Email! Complete OTP Verification to recover your account!",
		});
	} catch (error) {
		next(error);
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
				avatarUrl: user.profile?.avatarUrl,
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
	try {
		const { otp, email }: z.infer<typeof otpSchema> = req.body;
		const purposeValue = req.query.purpose;
		if (!purposeValue || typeof purposeValue !== "string") {
			return res.status(400).json({ message: "OTP purpose is required!" });
		}
		if (purposeValue === "ve-em-or") {
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
			const user = await userModel.findOne({ _id: userId });
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			if (user.isVerified) {
				return res.status(400).json({ message: "Email Already Verified!" });
			}
			user.isVerified = true;
			await user.save();
			return res.status(200).json({
				message:
					"Email Verified Successfully! You can now login to your account!",
			});
		} else if (purposeValue === "ve-em-up") {
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
			const user = await userModel.findOne({ _id: userId });
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			if (user.isVerified) {
				return res.status(400).json({ message: "Email Already Verified!" });
			}
			user.email = otpResult.newValue;
			user.isVerified = true;
			await user.save();
			return res.status(200).json({
				message:
					"Email Updated Successfully! You can now login to your account!",
			});
		} else if (purposeValue === "re-pa") {
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
			const user = await userModel.findOne({ _id: userId });
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
			await sessionModel.revokeAllUserSessions(
				user._id.toString(),
				"Password Reset",
			);
			await user.save();
			return res.status(200).json({
				message:
					"Password Updated Successfully! You can now login to your account!",
			});
		} else if (purposeValue === "fr-pa") {
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				"forgotPassword",
			);

			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			return res.status(200).json({
				message:
					"OTP Verified Successfully! Complete Password Reset Procedure to reset your password!",
				data: {
					userId: otpResult.userId,
					userEmail: email,
				},
			});
		} else if (purposeValue === "ac-re") {
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
			const user = await userModel.findOne({ _id: userId, isDeleted: true });
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			if (user.status === "active") {
				return res
					.status(400)
					.json({ message: "Account is already recovered!" });
			}
			await user.restore();
			await user.save();
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
		next(error);
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

export async function getPhoneNumberController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const { phoneNumber } = req.body;
		const otp = generateOTP();
		const otpStoreResult = await otpService.storeOTP(
			phoneNumber,
			otp,
			"phoneVerification",
		);
		if (!otpStoreResult.success) {
			return res.status(500).json({
				message:
					otpStoreResult.message ||
					"Failed to store OTP. Please try again later.",
			});
		}
		await sendVerificationSMS(phoneNumber, otp);
		console.warn("OTP for phone verification:", otp);

		return res.status(200).json({
			message:
				"Phone number verification initiated! Please check your phone for the verification code.",
		});
	} catch (error) {
		next(error);
	}
}

export async function verifyPhoneController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const { phoneNumber, otp }: z.infer<typeof phoneVerificationSchema> =
			req.body;
		const result = await otpService.verifyOTP(
			phoneNumber,
			otp,
			"phoneVerification",
		);
		if (!result.success) {
			return res.status(400).json({ message: result.message });
		}
		const user = await userModel.findOneAndUpdate(
			{ phoneNumber },
			{ isPhoneVerified: true },
		);
		if (!user) {
			return res
				.status(404)
				.json({ message: "User Not Found! | Failed to verify phone number." });
		}
		return res.status(200).json({
			message: "Phone verification successful!",
		});
	} catch (error) {
		next(error);
	}
}

export async function forgotPasswordEmailController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const { email } = req.body;
		const fieldToUpdate = "forgotPassword";
		if (!email) {
			return res.status(400).json({ message: "Email is required!" });
		}
		const user = await userModel.findOne({ email });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const otp = generateOTP();
		const html = getOtpHTML(otp, "resetPassword");

		const mailSuccess = await sendVerificationEmail(
			config.GMAIL_USER_EMAIL,
			user.email,
			emailPurposeMapper(fieldToUpdate),
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
			"forgotPassword",
			user._id.toString(),
		);

		if (!otpStoreSuccess.success) {
			return res.status(500).json({
				message: "Failed to store OTP. Please try again later.",
				success: false,
			});
		}

		return res.status(200).json({
			message:
				"OTP Sent to your Email! Complete OTP Verification to reset your password!",
			data: { email },
		});
	} catch (error) {
		next(error);
	}
}

export async function forgotPasswordUpdateController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		const { userId, userEmail, newPassword } = req.body;
		if (!userEmail || !newPassword) {
			return res
				.status(400)
				.json({ message: "Email	 and New Password are required!" });
		}
		const user = await userModel.findOne({ _id: userId, email: userEmail });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		if (!user.isVerified) {
			return res.status(400).json({ message: "Email Not Verified!" });
		}
		const isSameAsOldPassword = await user.isPasswordReused(newPassword);
		if (isSameAsOldPassword) {
			return res
				.status(400)
				.json({ message: "New Password cannot be same as last  password!" });
		}
		user.passwordHash = newPassword;
		user.isVerified = true;
		await sessionModel.revokeAllUserSessions(
			user._id.toString(),
			"Password Reset",
		);
		await user.save();
		return res.status(200).json({
			message:
				"Password Updated Successfully! You can now login to your account!",
			success: true,
		});
	} catch (error) {
		next(error);
	}
}
