import jwt, { type JwtPayload } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { config } from "../../../configs/app.config.js";
import type { NextFunction, Request, Response } from "express";
import {
	emailPurposeMapper,
	sendAndStoreOTP,
	AUTH_OTP_PURPOSES,
	OTP_PREFIX,
	generateTOTPSecret,
	verifyTOTP,
	RequestWithUser,
	issueTokensAndCreateSession,
} from "../utils/authcontroller.utils.js";
import { generateCsrfToken } from "../../../middlewares/csrf.middleware.js";
import * as z from "zod";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import type {
	otpResendSchema,
	loginDeleteRecoverAccSchema,
	otpSchema,
	registerSchema,
	usernameSchema,
	updateDetailsSchema,
	phoneVerificationSchema,
	profileUpdateSchema,
	emailSchema,
	twoFAVerifySchema,
	totpSchema,
} from "../../../libs/zod/auth.zodschema.js";
import { otpService } from "../../../services/redisotp.service.js";
import { sendVerificationSMS } from "../../../services/twilio.service.js";
import { RequestWithFileUrl } from "../../../middlewares/fileupload.middleware.js";

import {
	UserDocument,
	UserStaticMethods,
} from "../../../types/mongoModels/user.type.js";
import {
	SessionDocument,
	SessionStaticMethods,
} from "../../../types/mongoModels/session.type.js";
import { Model } from "mongoose";
import { generateOTP } from "../../../utils/nodemailer.utils.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";

export async function registerController(
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
) {
	const { username, email, password }: z.infer<typeof registerSchema> =
		req.body;
	try {
		const existingUser: UserDocument | null = await userModel.findOne({
			email,
			isVerified: true,
		});
		if (existingUser) {
			return res
				.status(409)
				.json({ message: "Email Already In Use.Go to Login" });
		}
		const existingUnverifiedUser: UserDocument | null = await userModel.findOne(
			{
				email,
				isVerified: false,
			},
		);

		if (existingUnverifiedUser) {
			const result = await sendAndStoreOTP(
				existingUnverifiedUser.email,
				AUTH_OTP_PURPOSES.VERIFY_EMAIL_REGISTER,
				existingUnverifiedUser._id.toString(),
				"resendOtp",
			);
			if (!result.success) {
				return res.status(503).json({ message: result.message });
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
		const result = await sendAndStoreOTP(
			email,
			AUTH_OTP_PURPOSES.VERIFY_EMAIL_REGISTER,
			String(user[0]?._id.toString()),
			"verifyEmailOR",
		);
		if (!result.success) {
			return res.status(503).json({ message: result.message });
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
	userModel: Model<UserDocument, UserStaticMethods>,
	sessionModel: SessionStaticMethods,
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

		const isUser: UserDocument | null = await userModel
			.findOne({ email })
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
		let devId;
		if (!req.cookies.devid) {
			devId = uuidv4();
		} else {
			devId = req.cookies.devid;
		}
		if (isUser.is2FAEnabled) {
			const tempToken = jwt.sign(
				{ id: isUser._id, type: "temp" },
				config.TEMP_TOKEN_JWT_SECRET,
				{ expiresIn: "10m" },
			);
			res.cookie("devid", devId, {
				httpOnly: true,
				secure: true,
				sameSite: "lax",
				maxAge: 600000,
			});
			res.cookie("tempToken", tempToken, {
				httpOnly: true,
				secure: true,
				sameSite: "lax",
				maxAge: 600000,
			});
			{
				return res.status(200).json({
					success: true,
					twoFARequired: true,
					message: "Enter your 2FA code to complete login",
				});
			}
		} else {
			return issueTokensAndCreateSession(
				req,
				res,
				next,
				sessionModel,
				isUser,
				devId,
			);
		}
	} catch (error) {
		next(error);
	}
}

export async function tokenRotationController(
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	sessionModel: SessionStaticMethods,
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
		const user: UserDocument | null = await userModel.findOne({
			_id: rfTokenDecoded.id,
		});

		if (!user) {
			return res.status(422).json({
				message: "Error Occured in User Validation !",
			});
		}

		const tokenFamily = crypto.randomBytes(16).toString("hex");

		const acToken = jwt.sign(
			{ id: user._id, sessionId: session._id.toString(), type: "access" },
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
	userModel: Model<UserDocument, UserStaticMethods>,
	sessionModel: SessionStaticMethods,
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

		// Decrement activeSessions count
		const user: UserDocument | null = await userModel.findById(
			rfTokenDecoded.id,
		);
		if (user && user.activeSessions > 0) {
			user.activeSessions -= 1;
			await user.save();
		}

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
	userModel: Model<UserDocument, UserStaticMethods>,
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
		const user: UserDocument | null = await userModel
			.findById(decodedToken.id)
			.select("+passwordHash");
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
				return res
					.status(200)
					.json({ message: "Username updated successfully!" });
			case "email": {
				const result = await sendAndStoreOTP(
					user.email,
					AUTH_OTP_PURPOSES.VERIFY_CURRENT_EMAIL,
					user._id.toString(),
					"verifyCurrentEmail",
					newValue,
				);
				if (!result.success) {
					return res.status(503).json({ message: result.message });
				}
				break;
			}
			case "password": {
				const newPasswordHash = await bcrypt.hash(newValue, 12);
				const result = await sendAndStoreOTP(
					user.email,
					AUTH_OTP_PURPOSES.RESET_PASSWORD,
					user._id.toString(),
					"resetPassword",
					newPasswordHash,
				);
				if (!result.success) {
					return res.status(503).json({ message: result.message });
				}
				break;
			}
			default:
				return res.status(400).json({ message: "Invalid Field to Update!" });
		}
		return res.status(200).json({
			message:
				"OTP sent to your current email! Verify via /verify?purpose=ve-em-cu",
		});
	} catch (error) {
		next(error);
	}
}

export async function updateProfile(
	req: RequestWithFileUrl,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
) {
	try {
		const { newValue }: z.infer<typeof profileUpdateSchema> = req.body;
		const fileUrl = req.fileUrl;

		const decodedToken = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const user: UserDocument | null = await userModel.findOne({
			_id: decodedToken.id,
		});
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const profileUpdationDetails = {
			...user.profile,
			...newValue,
			...(fileUrl && { avatarUrl: fileUrl }),
		};
		if (!profileUpdationDetails) {
			return res
				.status(400)
				.json({ message: "No valid profile data provided for update!" });
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
	userModel: Model<UserDocument, UserStaticMethods>,
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
		const user: UserDocument | null = await userModel
			.findOne({ email })
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
	userModel: Model<UserDocument, UserStaticMethods>,
	sessionModel: SessionStaticMethods,
) {
	try {
		const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> =
			req.body;
		const user: UserDocument | null = await userModel
			.findOne({ email })
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
		const result = await sendAndStoreOTP(
			user.email,
			AUTH_OTP_PURPOSES.ACCOUNT_RECOVERY,
			user._id.toString(),
			"accountRecovery",
		);
		if (!result.success) {
			return res.status(503).json({ message: result.message });
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
	userModel: Model<UserDocument, UserStaticMethods>,
) {
	try {
		const accessToken = req.cookies.acToken;
		const decodedToken = jwt.verify(
			accessToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const user: UserDocument | null = await userModel.findOne({
			_id: decodedToken.id,
		});

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
				role: user.role,
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
	userModel: Model<UserDocument, UserStaticMethods>,
	sessionModel: SessionStaticMethods,
) {
	try {
		const { otp, email }: z.infer<typeof otpSchema> = req.body;
		const purposeValue = req.query.purpose;
		if (!purposeValue || typeof purposeValue !== "string") {
			return res.status(400).json({ message: "OTP purpose is required!" });
		}
		if (purposeValue === AUTH_OTP_PURPOSES.VERIFY_EMAIL_REGISTER) {
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				AUTH_OTP_PURPOSES.VERIFY_EMAIL_REGISTER,
				OTP_PREFIX,
			);
			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			const userId = otpResult.userId;
			if (!userId) {
				return res.status(400).json({
					message:
						"Invalid OTP verification attempt. Please try registering after some time.",
				});
			}
			const user: UserDocument | null = await userModel.findOne({
				_id: userId,
			});
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
		} else if (purposeValue === AUTH_OTP_PURPOSES.VERIFY_CURRENT_EMAIL) {
			// Step 2: verify OTP on current email → send OTP to new email
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				AUTH_OTP_PURPOSES.VERIFY_CURRENT_EMAIL,
				OTP_PREFIX,
			);
			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			if (!otpResult.newValue || !otpResult.userId) {
				return res.status(400).json({
					message: "Invalid OTP data. Please restart the email update process.",
				});
			}
			const sendResult = await sendAndStoreOTP(
				otpResult.newValue,
				AUTH_OTP_PURPOSES.VERIFY_NEW_EMAIL,
				otpResult.userId,
				"verifyEmailUP",
			);
			if (!sendResult.success) {
				return res.status(503).json({ message: sendResult.message });
			}
			return res.status(200).json({
				message:
					"Current email verified! OTP sent to your new email. Complete verification to update.",
			});
		} else if (purposeValue === AUTH_OTP_PURPOSES.VERIFY_NEW_EMAIL) {
			// Step 3: verify OTP on new email → commit email change
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				AUTH_OTP_PURPOSES.VERIFY_NEW_EMAIL,
				OTP_PREFIX,
			);
			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			if (!otpResult.userId) {
				return res.status(400).json({
					message: "Invalid OTP data. Please restart the email update process.",
				});
			}
			const user: UserDocument | null = await userModel.findById(
				otpResult.userId,
			);
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			user.email = email;
			await user.save();
			return res.status(200).json({ message: "Email updated successfully!" });
		} else if (purposeValue === AUTH_OTP_PURPOSES.RESET_PASSWORD) {
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				AUTH_OTP_PURPOSES.RESET_PASSWORD,
				OTP_PREFIX,
			);
			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			if (!otpResult.newValue || !otpResult.userId) {
				return res.status(400).json({
					message:
						"Invalid OTP data. Please restart the password reset process.",
				});
			}
			const user: UserDocument | null = await userModel.findOne({
				_id: otpResult.userId,
			});
			if (!user) {
				return res.status(404).json({ message: "User Not Found!" });
			}
			const isSameAsOldPassword = await user.isPasswordReused(
				otpResult.newValue,
			);
			if (isSameAsOldPassword) {
				return res
					.status(400)
					.json({ message: "New Password cannot be same as last password!" });
			}
			user.passwordHash = otpResult.newValue;
			await sessionModel.revokeAllUserSessions(
				user._id.toString(),
				"Password Reset",
			);
			await user.save();
			return res.status(200).json({
				message:
					"Password Updated Successfully! You can now login to your account!",
			});
		} else if (purposeValue === AUTH_OTP_PURPOSES.FORGOT_PASSWORD) {
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				AUTH_OTP_PURPOSES.FORGOT_PASSWORD_INIT,
				OTP_PREFIX,
			);
			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			return res.status(200).json({
				message:
					"OTP Verified Successfully! Complete Password Reset Procedure to reset your password!",
				data: { userId: otpResult.userId, userEmail: email },
			});
		} else if (purposeValue === AUTH_OTP_PURPOSES.ACCOUNT_RECOVERY) {
			const otpResult = await otpService.verifyOTP(
				email,
				otp,
				AUTH_OTP_PURPOSES.ACCOUNT_RECOVERY,
				OTP_PREFIX,
			);
			if (!otpResult.success) {
				return res.status(400).json({ message: otpResult.message });
			}
			if (!otpResult.userId) {
				return res.status(400).json({
					message: "Invalid OTP verification attempt. Please try again.",
				});
			}
			const user: UserDocument | null = await userModel.findOne({
				_id: otpResult.userId,
				isDeleted: true,
			});
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
	userModel: Model<UserDocument, UserStaticMethods>,
) {
	try {
		const purpose = req.query.purpose;
		const { email }: z.infer<typeof otpResendSchema> = req.body;
		if (!purpose || typeof purpose !== "string") {
			return res.status(400).json({ message: "OTP purpose is required!" });
		}
		const user: UserDocument | null = await userModel.findOne({ email });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const result = await sendAndStoreOTP(
			email,
			purpose,
			user._id.toString(),
			"resendOtp",
		);
		if (!result.success) {
			return res.status(503).json({ message: result.message });
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
	userModel: Model<UserDocument, UserStaticMethods>,
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
		const user: UserDocument | null = await userModel.findOneAndUpdate(
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
	userModel: Model<UserDocument, UserStaticMethods>,
) {
	try {
		const { email } = req.body;
		if (!email) {
			return res.status(400).json({ message: "Email is required!" });
		}
		const user: UserDocument | null = await userModel.findOne({ email });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const result = await sendAndStoreOTP(
			email,
			AUTH_OTP_PURPOSES.FORGOT_PASSWORD_INIT,
			user._id.toString(),
			"resetPassword",
		);
		if (!result.success) {
			return res.status(503).json({ message: result.message });
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

// Enable 2FA
export const enable2FAController = async (
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) => {
	try {
		const id = req.userID;
		console.log("############1: User ID received in enable2FAController", id);
		if (!id) {
			return res
				.status(400)
				.json(standardResponse(false, "User ID not found in request", null));
		}

		const user = await userModel.findById(id);
		if (!user) {
			return res
				.status(404)
				.json(standardResponse(false, "User Not Found", null));
		}
		console.log("############2: User found in enable2FAController", user);
		const email = user.email;
		const twoFaQrData = await generateTOTPSecret(email);
		if (!twoFaQrData) {
			return res
				.status(500)
				.json(
					standardResponse(
						false,
						"Failed To generate qr! please try again later.",
					),
				);
		}
		console.log(
			"############3: QR Data generated in enable2FAController",
			twoFaQrData,
		);
		user.pending2FASecret = twoFaQrData.base32;
		await user.save();
		res.status(201).json(
			standardResponse(true, "Successfully created qr code for 2FA.", {
				qrCodeDataURL: twoFaQrData.qrCodeDataURL,
			}),
		);
	} catch (error: any) {
		next(error);
	}
};

// Verify 2FA during login
export const verify2FAController = async (
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
	sessionModel: SessionStaticMethods,
) => {
	try {
		const tempToken = req.cookies.tempToken;
		if (!tempToken) {
			return res.status(400).json({
				message: "Temporary Token Not Found !",
			});
		}

		const decodedTempToken = jwt.verify(
			tempToken,
			config.TEMP_TOKEN_JWT_SECRET,
		) as JwtPayload;
		if (!decodedTempToken || decodedTempToken.type !== "temp") {
			return res.status(400).json({
				message: "Invalid Temporary Token !",
			});
		}

		const id = decodedTempToken.id;
		if (!id) {
			return res
				.status(400)
				.json(standardResponse(false, "User ID not found in request", null));
		}

		const { token } = (req as any).body;
		if (!id || !token) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required Fields", null));
		}

		const user = await userModel.findById(id).select("+twoFASecret");
		if (!user) {
			return res
				.status(404)
				.json(standardResponse(false, "User Not found", null));
		}

		if (!user.is2FAEnabled || !user.twoFASecret) {
			return res.status(400).json({ message: "2FA not enabled" });
		}

		const isValid = verifyTOTP(user.twoFASecret, token);

		if (!isValid) {
			return res.status(401).json({ message: "Invalid or expired token" });
		}

		const deviceId = req.cookies.devid;
		if (!deviceId) {
			return res
				.status(400)
				.json(standardResponse(false, "Device ID not found in request", null));
		}

		return issueTokensAndCreateSession(
			req,
			res,
			next,
			sessionModel,
			user,
			deviceId,
		);
	} catch (error: any) {
		next(error);
	}
};

export async function disable2FAController(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const id = req.userID;
		if (!id) {
			return res
				.status(400)
				.json(standardResponse(false, "User ID not found in request", null));
		}
		const { token } = (req as any).body;
		if (!token) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required Fields", null));
		}

		const user = await userModel.findById(id).select("+twoFASecret");
		if (!user) {
			return res
				.status(404)
				.json(standardResponse(false, "User Not found", null));
		}
		if (!user.is2FAEnabled || !user.twoFASecret) {
			return res.status(400).json({ message: "2FA not enabled" });
		}

		const isValid = verifyTOTP(user.twoFASecret, token);

		if (!isValid) {
			return res.status(401).json({ message: "Invalid or expired token" });
		}

		user.twoFASecret = "";
		user.is2FAEnabled = false;
		user.twoFA_Options = "none";
		await user.save();

		res.status(200).json(standardResponse(true, "2FA Disabled Successfully!"));
	} catch (error: any) {
		next(error);
	}
}

export const confirm2FAController = async (
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) => {
	try {
		const id = req.userID;
		if (!id) {
			return res
				.status(400)
				.json(standardResponse(false, "User ID not found in request", null));
		}
		const { token } = (req as any).body;
		if (
			!token ||
			typeof token !== "string" ||
			token.trim() === "" ||
			token.length !== 6
		) {
			return res
				.status(400)
				.json(standardResponse(false, "Token is required", null));
		}
		const user = await userModel.findById(id).select("+pending2FASecret");
		if (!user) {
			return res
				.status(404)
				.json(standardResponse(false, "User Not Found", null));
		}
		console.log(user);
		console.log(user.pending2FASecret, "############# pending 2FA secret");
		if (!user.pending2FASecret) {
			return res
				.status(400)
				.json(standardResponse(false, "No pending 2FA setup found."));
		}

		const isValid = verifyTOTP(user.pending2FASecret, token);
		if (!isValid) {
			return res
				.status(401)
				.json(standardResponse(false, "Invalid code. Try again."));
		}

		// promote pending → confirmed, clear the pending slot
		user.twoFASecret = user.pending2FASecret;
		user.pending2FASecret = null;
		user.is2FAEnabled = true;
		user.twoFA_Options = "authenticator";
		await user.save();

		res.status(200).json(standardResponse(true, "2FA enabled successfully."));
	} catch (error: any) {
		next(error);
	}
};
