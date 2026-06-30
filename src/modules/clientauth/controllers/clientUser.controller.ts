import type { NextFunction, Request, Response } from "express";
import type * as z from "zod";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { otpService } from "../../../services/redisotp.service.js";
import { clientUserUtils } from "../utils/clientUserUtils.js";
import { AUTH_CONSTANTS, CLIENT_OTP_PURPOSES, CLIENT_REDIS_PREFIXES } from "../../../constants.js";
import type { ClientUserStaticMethods } from "../types/userMongo.type.js";
import type {
	RegisterSchema,
	LoginSchema,
	UpdateUsernameSchema,
	ResendOTPSchema,
	DeleteAccountSchema,
	RecoverAccountSchema,
	UpdateEmailSchema,
	ForgotPasswordSchema,
	UpdatePasswordSchema,
	VerifyEmailOnRegisterSchema,
	VerifyNewEmailSchema,
	VerifyForgotPasswordSchema,
	VerifyUpdatePasswordSchema,
	VerifyAccountRecoverySchema,
} from "../utils/zodSchemas.js";
import { OTP_PREFIX, sendAndStoreOTP } from "../utils/clientUserController.utils.js";

type RequestWithApiOwner = Request & { apiOwnerId?: string };
type UserModel = ClientUserStaticMethods;

// ─── Register ─────────────────────────────────────────────────────────────────

export async function registerController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { username, email, password }: z.infer<typeof RegisterSchema> = req.body;
		const clientId = req.apiOwnerId!;

		const alreadyExists = await userModel.emailExists(clientId, email);
		if (alreadyExists) {
			return res.status(409).json(standardResponse(false, "Email already registered"));
		}

		const passwordHash = await clientUserUtils.hashPassword(password);

		const doc = await userModel.create({
			clientId,
			email: email.toLowerCase().trim(),
			passwordHash,
			username: username?.toLowerCase(),
			authProvider: "email",
			emailVerified: false,
			profile: {},
			role: "user",
			status: "pending",
			twoFactorEnabled: false,
			failedLoginAttempts: 0,
			isDeleted: false,
		});

		const result = await sendAndStoreOTP(
			email,
			CLIENT_OTP_PURPOSES.VERIFY_EMAIL_REGISTER,
			doc._id.toString(),
			"verifyEmailOR",
		);

		if (!result.success) {
			await userModel.deleteOne({ _id: doc._id });
			return res.status(503).json(standardResponse(false, result.message!));
		}

		return res.status(201).json(standardResponse(true, "Registered successfully. Verification OTP sent to your email.", {
			docId: doc._id,
		}));
	} catch (error) {
		next(error);
	}
}

// ─── Login ────────────────────────────────────────────────────────────────────

export async function loginController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { email, password }: z.infer<typeof LoginSchema> = req.body;
		const clientId = req.apiOwnerId!;

		const user = await userModel.findByEmail(clientId, email).select("+passwordHash");
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		if (clientUserUtils.isLocked(user)) {
			return res.status(403).json(standardResponse(false, "Account is temporarily locked. Try again later."));
		}
		if (!user.emailVerified) {
			return res.status(403).json(standardResponse(false, "Email not verified. Please verify your email first."));
		}
		if (user.status !== "active") {
			return res.status(403).json(standardResponse(false, "Account is not active."));
		}
		if (!user.passwordHash) {
			return res.status(403).json(standardResponse(false, "Password login not available for this account."));
		}

		const isPasswordValid = await clientUserUtils.comparePassword(password, user.passwordHash);
		if (!isPasswordValid) {
			const updated = clientUserUtils.incrementFailedLogin(user);

			// Build $set selectively — only include lock fields if a lock was actually applied
			const failFields: Record<string, unknown> = {
				failedLoginAttempts: updated.failedLoginAttempts,
				lastFailedLoginAt: updated.lastFailedLoginAt,
			};
			if (updated.accountLockedUntil) {
				failFields.accountLockedUntil = updated.accountLockedUntil;
			}
			if (updated.status === "suspended") {
				failFields.status = "suspended";
			}

			await userModel.findOneAndUpdate(
				{ _id: user._id },
				{ $set: failFields },
			);
			return res.status(401).json(standardResponse(false, "Invalid password."));
		}

		await userModel.findOneAndUpdate(
			{ _id: user._id },
			{
				$set: {
					failedLoginAttempts: 0,
					lastLoginAt: new Date(),
					lastActiveAt: new Date(),
					lastLoginIp: req.ip ?? "unknown",
				},
				$unset: { accountLockedUntil: "", lastFailedLoginAt: "" },
			},
		);

		return res.status(200).json(standardResponse(true, "Login successful", {
			docId: user._id,
			email: user.email,
			username: user.username,
			role: user.role,
			profile: user.profile,
		}));
	} catch (error) {
		next(error);
	}
}

// ─── Logout ───────────────────────────────────────────────────────────────────

export async function logoutController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { docId } = req.body as { docId: string };
		const clientId = req.apiOwnerId!;

		if (!docId) {
			return res.status(400).json(standardResponse(false, "docId is required"));
		}

		await userModel.findOneAndUpdate(
			{ clientId, _id: docId },
			{ $set: { lastActiveAt: new Date() } },
		);

		return res.status(200).json(standardResponse(true, "Logged out successfully."));
	} catch (error) {
		next(error);
	}
}

// ─── Unified OTP Verification ─────────────────────────────────────────────────
// Purpose values (from CLIENT_OTP_PURPOSES in constants.ts):
//   ve-em-or  → verify email on registration      body: { email, otp }
//   ve-em-up  → verify new email after update     body: { newEmail, otp }
//   fr-pa     → forgot-password OTP + reset       body: { email, otp, newPassword }
//   up-pa     → authenticated password update     body: { docId, otp, newPassword }
//   ac-re     → account recovery OTP              body: { email, otp }
// User lookup + state checks run BEFORE Redis OTP verify in every case.

export async function verifyOTPController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const clientId = req.apiOwnerId!;
		const purpose = req.query.purpose;

		if (!purpose || typeof purpose !== "string") {
			return res.status(400).json(standardResponse(false, "?purpose query param is required"));
		}

		const VALID_PURPOSES = Object.values(CLIENT_OTP_PURPOSES);
		if (!VALID_PURPOSES.includes(purpose as typeof VALID_PURPOSES[number])) {
			return res.status(400).json(standardResponse(false, `Invalid purpose. Must be one of: ${VALID_PURPOSES.join(", ")}`));
		}

		switch (purpose) {

			// ── Verify email on registration ─────────────────────────────────────
			case CLIENT_OTP_PURPOSES.VERIFY_EMAIL_REGISTER: {
				const { email, otp }: z.infer<typeof VerifyEmailOnRegisterSchema> = req.body;

				const user = await userModel.findByEmail(clientId, email);
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}
				if (user.emailVerified) {
					return res.status(400).json(standardResponse(false, "Email is already verified"));
				}

				const otpResult = await otpService.verifyOTP(email, otp, CLIENT_OTP_PURPOSES.VERIFY_EMAIL_REGISTER, OTP_PREFIX);
				if (!otpResult.success) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}

				await userModel.findOneAndUpdate(
					{ clientId, _id: user._id },
					{ $set: { emailVerified: true, verifiedAt: new Date(), status: "active" } },
				);

				return res.status(200).json(standardResponse(true, "Email verified successfully. You can now login."));
			}

			// ── Verify new email (step 2 of email update) ────────────────────────
			case CLIENT_OTP_PURPOSES.VERIFY_NEW_EMAIL: {
				const { newEmail, otp }: z.infer<typeof VerifyNewEmailSchema> = req.body;

				// OTP stored against new email + docId as userId in Redis
				const otpResult = await otpService.verifyOTP(newEmail, otp, CLIENT_OTP_PURPOSES.VERIFY_NEW_EMAIL, OTP_PREFIX);
				if (!otpResult.success || !otpResult.userId) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}

				const user = await userModel.findByDocId(clientId, otpResult.userId);
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}

				const taken = await userModel.emailExists(clientId, newEmail);
				if (taken) {
					return res.status(409).json(standardResponse(false, "Email already in use"));
				}

				await userModel.findOneAndUpdate(
					{ clientId, _id: user._id },
					{ $set: { email: newEmail.toLowerCase().trim() } },
				);

				return res.status(200).json(standardResponse(true, "Email updated successfully."));
			}

			// ── Forgot password: verify OTP + reset password ─────────────────────
			case CLIENT_OTP_PURPOSES.FORGOT_PASSWORD: {
				const { email, otp, newPassword }: z.infer<typeof VerifyForgotPasswordSchema> = req.body;

				const user = await userModel.findByEmail(clientId, email).select("+passwordHash +lastPassword");
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}

				const otpResult = await otpService.verifyOTP(email, otp, CLIENT_OTP_PURPOSES.FORGOT_PASSWORD, OTP_PREFIX);
				if (!otpResult.success) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}

				const isReused = await clientUserUtils.isPasswordReused(newPassword, user.lastPassword);
				if (isReused) {
					return res.status(400).json(standardResponse(false, "New password cannot be the same as your last password"));
				}

				const newHash = await clientUserUtils.hashPassword(newPassword);
				await userModel.findOneAndUpdate(
					{ clientId, _id: user._id },
					{
						$set: {
							passwordHash: newHash,
							lastPassword: user.passwordHash,
							lastPasswordChangedAt: new Date(),
						},
					},
				);

				return res.status(200).json(standardResponse(true, "Password reset successfully. You can now login."));
			}

			// ── Authenticated password update: verify OTP + set new password ─────
			case CLIENT_OTP_PURPOSES.UPDATE_PASSWORD: {
				const { docId, otp, newPassword }: z.infer<typeof VerifyUpdatePasswordSchema> = req.body;

				const user = await userModel.findByDocId(clientId, docId).select("+passwordHash +lastPassword");
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}

				// OTP stored against user's registered email + up-pa purpose
				const otpResult = await otpService.verifyOTP(user.email, otp, CLIENT_OTP_PURPOSES.UPDATE_PASSWORD, OTP_PREFIX);
				if (!otpResult.success) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}

				const isReused = await clientUserUtils.isPasswordReused(newPassword, user.lastPassword);
				if (isReused) {
					return res.status(400).json(standardResponse(false, "New password cannot be the same as your last password"));
				}

				const newHash = await clientUserUtils.hashPassword(newPassword);
				await userModel.findOneAndUpdate(
					{ clientId, _id: user._id },
					{
						$set: {
							passwordHash: newHash,
							lastPassword: user.passwordHash,
							lastPasswordChangedAt: new Date(),
						},
					},
				);

				return res.status(200).json(standardResponse(true, "Password updated successfully."));
			}

			// ── Account recovery: verify OTP + restore account ───────────────────
			case CLIENT_OTP_PURPOSES.ACCOUNT_RECOVERY: {
				const { email, otp }: z.infer<typeof VerifyAccountRecoverySchema> = req.body;

				const user = await userModel.findByEmail(clientId, email);
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}
				if (!user.isDeleted) {
					return res.status(400).json(standardResponse(false, "Account is not scheduled for deletion"));
				}

				const otpResult = await otpService.verifyOTP(email, otp, CLIENT_OTP_PURPOSES.ACCOUNT_RECOVERY, OTP_PREFIX);
				if (!otpResult.success) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}

				await userModel.findOneAndUpdate(
					{ clientId, _id: user._id },
					{
						$set: {
							isDeleted: false,
							status: user.emailVerified ? "active" : "pending",
						},
						$unset: { deletedAt: "", scheduledDeletionAt: "" },
					},
				);

				return res.status(200).json(standardResponse(true, "Account recovered successfully. You can now login."));
			}
		}
	} catch (error) {
		next(error);
	}
}

// ─── Initiate Email Update ────────────────────────────────────────────────────
// Step 1: authenticated, confirms password, checks new email not taken,
//         sends OTP to the CURRENT email to confirm real user intent.
// Step 2: /verify?purpose=ve-em-up — sends OTP to new email after step 1 passes.
// Step 3: /verify?purpose=ve-em-up with newEmail+otp commits the change.

export async function initiateEmailUpdateController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { password, newEmail }: z.infer<typeof UpdateEmailSchema> = req.body;
		const { docId } = req.body as { docId: string };
		const clientId = req.apiOwnerId!;

		if (!docId) {
			return res.status(400).json(standardResponse(false, "docId is required"));
		}

		const user = await userModel.findByDocId(clientId, docId).select("+passwordHash");
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		if (!user.passwordHash) {
			return res.status(403).json(standardResponse(false, "Password login not available for this account"));
		}

		const isPasswordValid = await clientUserUtils.comparePassword(password, user.passwordHash);
		if (!isPasswordValid) {
			return res.status(401).json(standardResponse(false, "Invalid password"));
		}

		const taken = await userModel.emailExists(clientId, newEmail);
		if (taken) {
			return res.status(409).json(standardResponse(false, "Email already in use"));
		}

		// OTP sent to CURRENT email; newEmail stored as newValue in Redis
		// so that the ve-em-up verify case knows where to send the next OTP
		const result = await sendAndStoreOTP(
			user.email,
			CLIENT_OTP_PURPOSES.VERIFY_CURRENT_EMAIL,
			docId,
			"verifyCurrentEmail",
			newEmail,
		);
		if (!result.success) {
			return res.status(503).json(standardResponse(false, result.message!));
		}

		return res.status(200).json(standardResponse(true, "OTP sent to your current email. Verify via /verify?purpose=ve-em-cu"));
	} catch (error) {
		next(error);
	}
}

// ─── Initiate Forgot Password ─────────────────────────────────────────────────
// Unauthenticated. Sends OTP to registered email.
// Completed via /verify?purpose=fr-pa (OTP + newPassword in one call).

export async function initiateForgotPasswordController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { email }: z.infer<typeof ForgotPasswordSchema> = req.body;
		const clientId = req.apiOwnerId!;

		const user = await userModel.findByEmail(clientId, email);
		if (!user) {
			// Intentionally vague — prevents email enumeration
			return res.status(200).json(standardResponse(true, "If this email is registered, an OTP has been sent."));
		}

		const result = await sendAndStoreOTP(
			email,
			CLIENT_OTP_PURPOSES.FORGOT_PASSWORD,
			user._id.toString(),
			"resetPassword",
		);
		if (!result.success) {
			return res.status(503).json(standardResponse(false, result.message!));
		}

		return res.status(200).json(standardResponse(true, "If this email is registered, an OTP has been sent."));
	} catch (error) {
		next(error);
	}
}

// ─── Initiate Update Password ─────────────────────────────────────────────────
// Authenticated. Verifies current password, then sends OTP to registered email.
// Completed via /verify?purpose=up-pa (OTP + newPassword).

export async function initiateUpdatePasswordController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { oldPassword }: z.infer<typeof UpdatePasswordSchema> = req.body;
		const { docId } = req.body as { docId: string };
		const clientId = req.apiOwnerId!;

		if (!docId) {
			return res.status(400).json(standardResponse(false, "docId is required"));
		}

		const user = await userModel.findByDocId(clientId, docId).select("+passwordHash");
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		if (!user.passwordHash) {
			return res.status(403).json(standardResponse(false, "Password login not available for this account"));
		}

		const isOldValid = await clientUserUtils.comparePassword(oldPassword, user.passwordHash);
		if (!isOldValid) {
			return res.status(401).json(standardResponse(false, "Current password is incorrect"));
		}

		const result = await sendAndStoreOTP(
			user.email,
			CLIENT_OTP_PURPOSES.UPDATE_PASSWORD,
			docId,
			"updatePassword",
		);
		if (!result.success) {
			return res.status(503).json(standardResponse(false, result.message!));
		}

		return res.status(200).json(standardResponse(true, "OTP sent to your registered email. Verify via /verify?purpose=up-pa"));
	} catch (error) {
		next(error);
	}
}

// ─── Update Username ──────────────────────────────────────────────────────────
// Authenticated. Confirms user belongs to this client, no password needed.

export async function updateUsernameController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { newUsername }: z.infer<typeof UpdateUsernameSchema> = req.body;
		const { docId } = req.body as { docId: string };
		const clientId = req.apiOwnerId!;

		if (!docId) {
			return res.status(400).json(standardResponse(false, "docId is required"));
		}

		const user = await userModel.findByDocId(clientId, docId);
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		await userModel.findOneAndUpdate(
			{ clientId, _id: docId },
			{ $set: { username: newUsername.toLowerCase() } },
		);

		return res.status(200).json(standardResponse(true, "Username updated successfully"));
	} catch (error) {
		next(error);
	}
}

// ─── Resend OTP ───────────────────────────────────────────────────────────────

export async function resendOTPController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { email }: z.infer<typeof ResendOTPSchema> = req.body;
		const purpose = req.query.purpose;
		if (!purpose || typeof purpose !== "string") {
			return res.status(400).json(standardResponse(false, "?purpose query param is required"));
		}

		const VALID_PURPOSES = Object.values(CLIENT_OTP_PURPOSES);
		if (!VALID_PURPOSES.includes(purpose as typeof VALID_PURPOSES[number])) {
			return res.status(400).json(standardResponse(false, `Invalid purpose. Must be one of: ${VALID_PURPOSES.join(", ")}`));
		}

		const clientId = req.apiOwnerId!;

		const user = await userModel.findByEmail(clientId, email);
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		const result = await sendAndStoreOTP(
			email,
			purpose,
			user._id.toString(),
			"resendOtp",
		);
		if (!result.success) {
			return res.status(503).json(standardResponse(false, result.message!));
		}

		return res.status(200).json(standardResponse(true, "OTP resent successfully. Please check your email."));
	} catch (error) {
		next(error);
	}
}

// ─── Delete Account ───────────────────────────────────────────────────────────

export async function deleteAccountController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { password }: z.infer<typeof DeleteAccountSchema> = req.body;
		const { docId } = req.body as { docId: string };
		const clientId = req.apiOwnerId!;

		if (!docId) {
			return res.status(400).json(standardResponse(false, "docId is required"));
		}

		const user = await userModel.findByDocId(clientId, docId).select("+passwordHash");
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		if (!user.passwordHash) {
			return res.status(403).json(standardResponse(false, "Password login not available for this account"));
		}
		const isPasswordValid = await clientUserUtils.comparePassword(password, user.passwordHash);
		if (!isPasswordValid) {
			return res.status(401).json(standardResponse(false, "Invalid password"));
		}
		if (user.isDeleted) {
			return res.status(400).json(standardResponse(false, "Account already scheduled for deletion"));
		}

		const now = new Date();
		await userModel.findOneAndUpdate(
			{ clientId, _id: docId },
			{
				$set: {
					isDeleted: true,
					deletedAt: now,
					status: "deleted",
					scheduledDeletionAt: new Date(
						now.getTime() + AUTH_CONSTANTS.SOFT_DELETE_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
					),
				},
			},
		);

		return res.status(200).json(standardResponse(true, `Account scheduled for deletion. You can recover it within ${AUTH_CONSTANTS.SOFT_DELETE_GRACE_PERIOD_DAYS} days.`));
	} catch (error) {
		next(error);
	}
}

// ─── Recover Account ──────────────────────────────────────────────────────────
// Unauthenticated. Sends OTP to registered email.
// Completed via /verify?purpose=ac-re.

export async function recoverAccountController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserModel,
) {
	try {
		const { email }: z.infer<typeof RecoverAccountSchema> = req.body;
		const clientId = req.apiOwnerId!;

		const user = await userModel.findByEmail(clientId, email);
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		if (!user.isDeleted) {
			return res.status(400).json(standardResponse(false, "Account is not scheduled for deletion"));
		}

		const result = await sendAndStoreOTP(
			email,
			CLIENT_OTP_PURPOSES.ACCOUNT_RECOVERY,
			user._id.toString(),
			"accountRecovery",
		);
		if (!result.success) {
			return res.status(503).json(standardResponse(false, result.message!));
		}

		return res.status(200).json(standardResponse(true, "OTP sent to your email. Verify via /verify?purpose=ac-re to complete recovery."));
	} catch (error) {
		next(error);
	}
}
