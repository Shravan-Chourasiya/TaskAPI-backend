import { userModel } from "../models/user.model.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { sessionModel } from "../models/session.model.js";
import { config } from "../../../configs/configs.js";
import { generateOTP, getOtpHTML } from "../../../utils/email.utils.js";
import { sendVerificationEmail } from "../../../services/email.service.js";
import { OtpModel, OtpModel as otpModel } from "../models/otp.model.js";
import type { NextFunction, Request, Response } from "express";
import {
	AccountRecoveryHandler,
	emailPurposeMapper,
	EmailUpdationHandler,
	EmailVerificationHandler,
	ResetPasswordHandler,
} from "../utils/authcontroller.utils.js";
import * as z from "zod";
import type { usernameSchema } from "../../../libs/zodschemas.js";

export async function registerController(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	const { username, email, password } = req.body;
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
			const otpHash = await bcrypt.hash(otp, 12);

			const otpObject = await OtpModel.create({
				userId: existingUnverifiedUser._id,
				otp: otpHash,
				email: existingUnverifiedUser.email,
				purpose: emailSubject,
			});
			return res.status(409).json({
				message:
					"Email Already Registered but not verified! Verification OTP sent to your email . Verify Email and complete registration!",
			});
		}
		const hashedPass = await bcrypt.hash(password, 12);
		const user = await userModel.create({
			username,
			email,
			password: hashedPass,
		});

		if (!user) {
			return res.status(503).json({
				message: "User Not Registered.Please try again Later!",
			});
		}
		const tempToken = jwt.sign({ id: user._id }, config.JWT_SECRET, {
			expiresIn: "10m",
		});

		res.cookie("tempToken", tempToken, {
			...config.COOKIE_CONF_TT,
			maxAge: 10 * 60 * 1000,
		});
		const otp = generateOTP();
		const html = getOtpHTML(otp, "verifyEmailOR");

		const mailSuccess = await sendVerificationEmail(
			config.GMAIL_USER_EMAIL as string,
			email,
			"Email Verification on TaskAPI",
			html,
		);
		if (!mailSuccess) {
			await user.deleteOne();
			return res.status(503).json({
				message:
					"Failed to send verification email. Please try registering again later.",
			});
		}
		const otpHash = await bcrypt.hash(otp, 12);
		const otpObject = await otpModel.create({
			userId: user._id,
			otp: otpHash,
			email: user.email,
			purpose: "verifyEmailOR",
		});

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
	try {
		const { usernameORemail, password } = req.body;
		const isUser = await userModel.findOne({
			$or: [{ username: usernameORemail }, { email: usernameORemail }],
		});
		if (!isUser) {
			return res.status(404).json({ message: "User Not Found!" });
		}
		const isPasswordCorrect = await bcrypt.compare(password, isUser.password);
		if (!isPasswordCorrect) {
			return res.status(403).json({ message: "Invalid Password.Try Again!" });
		}
		if (!isUser.isVerified) {
			return res
				.status(403)
				.json({ message: "User Not verified.Verify Your Email!" });
		}
		if (isUser.isDeleted) {
			return res.status(403).json({
				message:
					"Account Scheduled for Deletion! Complete Account Recovery Procedure within 30 days to recover your account!",
			});
		}
		const refreshToken = jwt.sign(
			{ id: isUser._id, ip: req.ip, ua: req.headers["user-agent"] },
			config.JWT_SECRET,
			{
				expiresIn: "7d",
			},
		);
		const accessToken = jwt.sign(
			{ id: isUser._id, email: isUser.email },
			config.JWT_SECRET_2,
			{ expiresIn: 600 },
		);
		const rfTokenHash = await bcrypt.hash(refreshToken, 12);
		const existingSession = await sessionModel
			.find({ userId: isUser._id, isRevoked: false })
			.sort({ createdAt: 1 });
		if (existingSession.length >= 5) {
			const oldestSession = existingSession[0];
			await sessionModel.deleteOne({ _id: oldestSession?._id });
			return res.status(403).json({
				message:
					"Maximum Session Limit Reached! Logged Out from Oldest Session!",
			});
		}
		const session = await sessionModel.create({
			userId: isUser._id,
			userIP: req.ip || "unknown",
			userAgents: req.headers["user-agent"] || "unknown",
			refreshToken: rfTokenHash,
		});

		res.cookie("rfToken", refreshToken, config.COOKIE_CONF_RT);
		res.cookie("acToken", accessToken, config.COOKIE_CONF_AT);
		return res.status(200).json({
			message: "User Logged in successfully!",
			data: {
				username: isUser.username,
				email: isUser.email,
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
				message: "Refresh token is invalid or revoked",
			});
		}
		await session.updateOne({ isRevoked: true });
		res.clearCookie("rfToken", config.COOKIE_CONF_RT);
		res.clearCookie("acToken", config.COOKIE_CONF_AT);
		res.status(200).json({
			message: "User Logged Out Successfully !",
		});
	} catch (error) {
		next(error);
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
