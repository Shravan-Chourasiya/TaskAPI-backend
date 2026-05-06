import jwt, { type JwtPayload } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { config } from "../../../configs/app.config.js";
import { generateOTP, getOtpHTML } from "../../../utils/email.utils.js";
import { sendVerificationEmail } from "../../../services/nodemailer.service.js";
import type { NextFunction, Request, Response } from "express";
import {
	AccountRecoveryHandler,
	emailPurposeMapper,
	EmailUpdationHandler,
	EmailVerificationHandler,
	ResetPasswordHandler,
} from "../utils/authcontroller.utils.js";
import * as z from "zod";
import crypto from "crypto";
import type {
	loginDeleteRecoverAccSchema,
	registerSchema,
	usernameSchema,
} from "../../../libs/zod/auth.zodschema.js";
import userModel from "../models/users/user.schema.js";
import otpModel from "../models/otp/otp.schema.js";
import { otpService } from "../../../services/redisotp.service.js";
import sessionModel from "../models/session/session.schema.js";

export async function registerController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const { username, email, password }: z.infer<typeof registerSchema> =
		req.body;
	const session = await userModel.db.startSession();
	try {
		session.startTransaction();

		const existingUser = await userModel.findOne(
			{ email, isVerified: true },
			{ session },
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
			{ session },
		);

		if (existingUnverifiedUser) {
			const emailSubject = "verifyEmailOR";
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

			if (!otpStoreSuccess) {
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
			{ session },
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
			"Email Verification on TaskAPI",
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
		if (!otpStoreSuccess) {
			return res.status(503).json({
				message: "Failed to store OTP. Please try again later.",
			});
		}

		await session.commitTransaction();

		return res.status(201).json({
			message:
				"User Registered Successfully! Verification OTP sent to your email . Verify Email and complete registration!",
		});
	} catch (error) {
		if (session) {
			await session.abortTransaction();
		}
		next(error);
	} finally {
		if (session) {
			await session.endSession();
		}
	}
}

export async function loginController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const { email, password }: z.infer<typeof loginDeleteRecoverAccSchema> = req.body;
	const Session = await userModel.db.startSession();
	try {
		if(req.cookies.acToken){
			return res.status(400).json({
				message: "Already Logged In! Please Logout from current session to login again!",
			});
		}
		Session.startTransaction();

		const isUser = await userModel.findOne({ email }, { session: Session }).select("+passwordHash");
		if (!isUser) {
			return res.status(404).json({ message: "User Not Found!" });
		}

		const isPasswordCorrect = await isUser.comparePassword(password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}

		if (!isUser.isVerified) {
			return res.status(403).json({
				message:
					"Email Not Verified! Verification OTP sent to your email . Verify Email and complete registration!",
			});
		}

		if (isUser.isDeleted) {
			return res.status(403).json({
				message:
					"Account Scheduled for Deletion! Complete Account Recovery Procedure to recover your account!",
			});
		}

		// Generate consistent deviceId from user agent
		const deviceId = crypto.createHash("sha256")
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
			{ id: isUser._id ,type: "access"},
			config.ACCESS_TOKEN_JWT_SECRET,
			{ expiresIn: "10m" },
		);

		const rfTokenHash = await bcrypt.hash(refreshToken, 12);
	const acTokenHash = await bcrypt.hash(accessToken, 12);

		// Check if session exists for this device
		const existingSession = await sessionModel.findOne({
			userId: isUser._id.toString(),
			deviceId: deviceId,
		}, { session: Session });
	
		if(existingSession){
		
			await existingSession.updateOne({
				accessTokenHash: acTokenHash,
				refreshTokenHash: rfTokenHash,
				tokenFamily,
				isRevoked: false,
				status: "active",
				lastActivityAt: new Date(),
				refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
			}, { session: Session });
		} else {
			const activeSessionCount = await sessionModel.countDocuments({
				userId: isUser._id.toString(),
				isRevoked: false,
			}, { session: Session });

			if (activeSessionCount >= 5) {
				return res.status(403).json({
					message: "Maximum 5 devices allowed. Logout from another device first.",
				});
			}

			const newSession = await sessionModel.create([{
				userId: isUser._id.toString(),
				deviceId: deviceId,
				userAgent: req.headers["user-agent"] || "unknown",
				ipAddress: req.ip || "unknown",
				ipCountry: req.headers["cf-ipcountry"]?.toString() || "unknown",
				ipRegion: req.headers["cf-ipregion"]?.toString() || "unknown",
				ipCity: req.headers["cf-ipcity"]?.toString() || "unknown",
				tokenFamily,
				refreshTokenHash: rfTokenHash,
				accessTokenHash: acTokenHash,
				isRevoked: false,
				status: "active",
				lastActivityAt:new Date(),
				refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
			}], { session: Session });

			if (!newSession) {
				return res.status(503).json({
					message: "Failed to create session. Please try again later.",
				});
			}
		}

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
	}finally{
		if(Session){
			await Session.endSession();
		}
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
		const rfTokenDecoded = jwt.verify(rfToken, config.JWT_SECRET) as JwtPayload;
		const session = await sessionModel.findOne({
			userId: rfTokenDecoded.id,
			userIP: rfTokenDecoded.ip,
			userAgents: rfTokenDecoded.ua,
			isRevoked: false,
		});
		if (!session) {
			return res.status(400).json({
				message: "Refresh token is invalid or revoked",
			});
		}
		const isRfTokenCorrect = await bcrypt.compare(
			rfToken,
			session.refreshToken,
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

		const acToken = jwt.sign(
			{ id: user._id, email: user.email },
			config.JWT_SECRET_2,
			{ expiresIn: 600 },
		);
		const newRfToken = jwt.sign(
			{ id: user._id, ip: req.ip, ua: req.headers["user-agent"] },
			config.JWT_SECRET,
			{
				expiresIn: "7d",
			},
		);
		const newRfTokenHash = await bcrypt.hash(newRfToken, 12);
		await session.updateOne({ refreshToken: newRfTokenHash, isRevoked: false });

		res.cookie("rfToken", newRfToken, config.COOKIE_CONF_RT);
		res.cookie("acToken", acToken, config.COOKIE_CONF_AT);
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
	const Session = await userModel.db.startSession();
	try {
		Session.startTransaction();

		const acToken = req.cookies.acToken;
		if (!acToken) {
			return res.status(400).json({
				message: "Access Token Not Found !",
			});
		}
		const acTokenDecoded = jwt.verify(acToken, config.ACCESS_TOKEN_JWT_SECRET) as JwtPayload;
		const session = await sessionModel.findOne({
			userId: acTokenDecoded.id,
			isRevoked: false,
		},{ session: Session }).select("+accessTokenHash");
		if (!session) {
			return res.status(400).json({
				message: "Access token is invalid or revoked | Session not found",
			});
		}
		const isAcTokenCorrect = await bcrypt.compare(
			acToken,
			session.accessTokenHash,
		);
		if (!isAcTokenCorrect) {
			return res.status(400).json({
				message: "Access token is invalid or revoked",
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
	try {
		const { fieldToUpdate, newValue, password } = req.body;
		const decodedToken = jwt.verify(
			req.cookies.acToken,
			config.JWT_SECRET_2,
		) as JwtPayload;
		const user = await userModel.findOne({ email: decodedToken.email });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const isPasswordCorrect = await bcrypt.compare(password, user.password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}
		switch (fieldToUpdate) {
			case "username":
				await user.updateOne({
					username: newValue as z.infer<typeof usernameSchema>,
				});
				break;
			case "email":
				const otp = generateOTP();
				const html = getOtpHTML(otp, "verifyEmailUP");
				const mailSuccess = await sendVerificationEmail(
					config.GMAIL_USER_EMAIL,
					user.email,
					"Email Verification on TaskAPI",
					html,
				);
				if (!mailSuccess) {
					return res.status(503).json({
						message:
							"Failed to send verification email. Please try again later.",
					});
				}
				const otpHash = await bcrypt.hash(otp, 12);
				const otpObject = await otpModel.create({
					userId: user._id,
					otp: otpHash,
					email: user.email,
					purpose: "verifyEmailUP",
					isTemp: true,
					fieldToUpdateNewValue: newValue,
				});
				break;
			case "password":
				const otp2 = generateOTP();
				const html2 = getOtpHTML(otp2, "resetPassword");

				const mailSuccess2 = await sendVerificationEmail(
					config.GMAIL_USER_EMAIL,
					user.email,
					"Password Reset Verification on TaskAPI",
					html2,
				);

				if (!mailSuccess2) {
					return res.status(503).json({
						message:
							"Failed to send verification email. Please try again later.",
					});
				}

				const otpHash2 = await bcrypt.hash(otp2, 12);
				const newPasswordHash = await bcrypt.hash(newValue, 12);
				const otpObject2 = await otpModel.create({
					userId: user._id,
					otp: otpHash2,
					email: user.email,
					purpose: "resetPassword",
					isTemp: true,
					fieldToUpdateNewValue: newPasswordHash,
				});
				break;
			default:
				return res.status(400).json({ message: "Invalid Field to Update!" });
		}
		await user.save();
		return res.status(200).json({
			message:
				"Verification OTP sent to your email! Complete OTP verification to update your details!",
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
		const { usernameORemail, password } = req.body;
		const user = await userModel.findOne({
			$or: [{ username: usernameORemail }, { email: usernameORemail }],
		});
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const isPasswordCorrect = await bcrypt.compare(password, user.password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}
		if (user.isDeleted) {
			return res
				.status(400)
				.json({ message: "Account Already Scheduled to be Deleted!" });
		}
		await user.updateOne({ isDeleted: true });
		return res.status(200).json({
			message:
				"Account Scheduled to be Deleted! If you want to recover it,Complete Account Recovery Procedure within 30 days and recover your account!",
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
		const { usernameORemail, password } = req.body;
		const user = await userModel.findOne({
			$or: [{ username: usernameORemail }, { email: usernameORemail }],
		});
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const isPasswordCorrect = await bcrypt.compare(password, user.password);
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
		const otpHash = await bcrypt.hash(otp, 12);
		const otpObject = await otpModel.create({
			userId: user._id,
			otp: otpHash,
			email: user.email,
			purpose: "account_recovery",
			isTemp: true,
		});
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
			config.JWT_SECRET_2,
		) as JwtPayload;
		const user = await userModel.findOne({ _id: decodedToken.id });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		if (user.isDeleted) {
			return res.status(400).json({
				message:
					"Account Scheduled for Deletion! Complete Account Recovery Procedure within 30 days to recover your account!",
			});
		}
		return res.status(200).json({
			message: "User Account Details Fetched Successfully!",
			data: {
				username: user.username,
				email: user.email,
				isVerified: user.isVerified,
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
		const { otp } = req.body;
		if (req.query.purpose === "ve-em-or") {
			return EmailVerificationHandler(otp)(req, res, next);
		} else if (req.query.purpose === "ve-em-up") {
			return EmailUpdationHandler(otp)(req, res, next);
		} else if (req.query.purpose === "re-pa") {
			return ResetPasswordHandler(otp)(req, res, next);
		} else if (req.query.purpose === "ac-re") {
			return AccountRecoveryHandler(otp)(req, res, next);
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
		const { email } = req.body;
		const user = await userModel.findOne({ email });
		if (!user) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const existingOtp = await otpModel
			.findOne({
				email,
				isUsed: false,
				attemptsLeft: { $gt: 0 },
				expiryTime: { $gt: new Date() },
			})
			.sort({ createdAt: -1 });

		if (!existingOtp) {
			return res.status(404).json({
				message:
					"No valid OTP request found. Please initiate a new verification process.",
			});
		}
		const purpose = existingOtp.purpose;

		const emailSubject = emailPurposeMapper(purpose);

		const otp = generateOTP();
		const html = getOtpHTML(otp, "resend_otp");

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
		const otpHash = await bcrypt.hash(otp, 12);
		const newAttemptsLeft =
			existingOtp.attemptsLeft > 0 ? existingOtp.attemptsLeft - 1 : 0;

		const otpObject = await OtpModel.create({
			userId: user._id,
			otp: otpHash,
			email: user.email,
			purpose,
			attemptsLeft: newAttemptsLeft,
		});

		await existingOtp.updateOne({
			isUsed: true,
			attemptsLeft: newAttemptsLeft,
		});

		return res.status(200).json({
			message: "OTP resent successfully! Please check your email.",
		});
	} catch (error) {
		next(error);
	}
}
