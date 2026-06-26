import type { NextFunction, Request, Response } from "express";
import type * as z from "zod";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { otpService } from "../../../services/redisotp.service.js";
import { sendVerificationEmail } from "../../../services/nodemailer.service.js";
import { generateOTP, getOtpHTML } from "../../../utils/nodemailer.utils.js";
import { hashEmail, clientUserUtils } from "../utils/clientUserUtils.js";
import { CLIENT_REDIS_PREFIXES } from "../../../constants.js";
import type {
	ClientUsersStoreDocument,
	ClientUsersStoreStaticMethods,
} from "../types/userMongo.type.js";
import type {
	RegisterSchema,
	LoginSchema,
	VerifyOTPSchema,
	ResendOTPSchema,
	ForgotPasswordSchema,
	UpdatePasswordSchema,
	UpdateUsernameSchema,
	UpdateEmailSchema,
	DeleteAccountSchema,
} from "../utils/zodSchemas.js";

type RequestWithApiOwner = Request & { apiOwnerId?: string };
type StoreModel = ClientUsersStoreStaticMethods;

const OTP_PREFIX = CLIENT_REDIS_PREFIXES.OTP_STORAGE; // "client:otp:"

// ─── Private helper: find user in store map by userId ─────────────────────────

async function findUserByIdInStore(store: ClientUsersStoreDocument, userId: string) {
	for (const [hash, u] of store.users) {
		if (u.userId === userId) return { emailHash: hash, user: u };
	}
	return null;
}

// ─── Register ─────────────────────────────────────────────────────────────────

export async function registerController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { username, email, password }: z.infer<typeof RegisterSchema> = req.body;
		const clientId = req.apiOwnerId!;
		const emailHash = hashEmail(email);

		const alreadyExists = await storeModel.userExists(clientId, emailHash);
		if (alreadyExists) {
			return res.status(409).json(standardResponse(false, "Email already registered"));
		}

		const passwordHash = await clientUserUtils.hashPassword(password);
		const newUser = clientUserUtils.createNewUser({ email, passwordHash, username });

		await storeModel.findOneAndUpdate(
			{ clientId },
			{
				$set: { [`users.${emailHash}`]: newUser },
				$inc: { userCount: 1 },
			},
			{ upsert: true },
		);

		const otp = generateOTP();
		const html = getOtpHTML(otp, "verifyEmailOR");
		const mailSent = await sendVerificationEmail(
			process.env.GMAIL_USER_EMAIL as string,
			email,
			"Verify your email",
			html,
		);
		if (!mailSent) {
			return res.status(503).json(standardResponse(false, "Failed to send verification email. Please try again later."));
		}

		const otpStored = await otpService.storeOTP(email, otp, "verifyEmailOR", newUser.userId, undefined, 600, OTP_PREFIX);
		if (!otpStored.success) {
			return res.status(503).json(standardResponse(false, otpStored.message || "Failed to store OTP. Please try again later."));
		}

		return res.status(201).json(standardResponse(true, "Registered successfully. Verification OTP sent to your email."));
	} catch (error) {
		next(error);
	}
}

// ─── Login ────────────────────────────────────────────────────────────────────

export async function loginController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { email, password }: z.infer<typeof LoginSchema> = req.body;
		const clientId = req.apiOwnerId!;
		const emailHash = hashEmail(email);

		const user = await storeModel.getUser(clientId, emailHash);
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
			updated.updatedAt = new Date();
			await storeModel.findOneAndUpdate(
				{ clientId },
				{ $set: { [`users.${emailHash}`]: updated } },
			);
			return res.status(401).json(standardResponse(false, "Invalid password."));
		}

		let updated = clientUserUtils.resetFailedLogin(user);
		updated = clientUserUtils.updateLoginActivity(updated, req.ip ?? "unknown");
		updated.updatedAt = new Date();

		await storeModel.findOneAndUpdate(
			{ clientId },
			{ $set: { [`users.${emailHash}`]: updated } },
		);

		return res.status(200).json(standardResponse(true, "Login successful", {
			userId: user.userId,
			email: user.email,
			username: user.username,
			role: user.role,
			profile: user.profile,
		}));
	} catch (error) {
		next(error);
	}
}

// ─── Centralised OTP Verification
// Verifies OTP and performs the associated action in one shot.
// ?purpose= query param:
//   ve-em-or → verify email on registration → activates account
//   ve-em-up → verify new email → swaps map key to new email
//   fr-pa    → verify forgot password OTP + update password in same call
//   ac-re    → verify account recovery OTP + restore account in same call

export async function verificationController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { email, otp }: z.infer<typeof VerifyOTPSchema> = req.body;
		const clientId = req.apiOwnerId!;
		const purposeValue = req.query.purpose;

		if (!purposeValue || typeof purposeValue !== "string") {
			return res.status(400).json(standardResponse(false, "OTP purpose is required"));
		}

		switch (purposeValue) {

			case "ve-em-or": {
				const otpResult = await otpService.verifyOTP(email, otp, "verifyEmailOR", OTP_PREFIX);
				if (!otpResult.success) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}
				const emailHash = hashEmail(email);
				const user = await storeModel.getUser(clientId, emailHash);
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}
				if (user.emailVerified) {
					return res.status(400).json(standardResponse(false, "Email already verified"));
				}
				const updated = clientUserUtils.verifyEmail(user);
				updated.updatedAt = new Date();
				await storeModel.findOneAndUpdate(
					{ clientId },
					{ $set: { [`users.${emailHash}`]: updated } },
				);
				return res.status(200).json(standardResponse(true, "Email verified successfully. You can now login."));
			}

			case "ve-em-up": {
				// email here is the NEW email (OTP was sent to new email)
				const otpResult = await otpService.verifyOTP(email, otp, "verifyEmailUP", OTP_PREFIX);
				if (!otpResult.success || !otpResult.userId || !otpResult.newValue) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}
				const store = await storeModel.findStore(clientId);
				if (!store) {
					return res.status(404).json(standardResponse(false, "Store not found"));
				}
				const found = await findUserByIdInStore(store, otpResult.userId);
				if (!found) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}
				const newEmail = otpResult.newValue;
				const newEmailHash = hashEmail(newEmail);
				const updatedUser = { ...found.user, email: newEmail, updatedAt: new Date() };
				await storeModel.findOneAndUpdate(
					{ clientId },
					{
						$set: { [`users.${newEmailHash}`]: updatedUser },
						$unset: { [`users.${found.emailHash}`]: "" },
					},
				);
				return res.status(200).json(standardResponse(true, "Email updated successfully."));
			}

			case "fr-pa": {
				// Verify OTP + update password in one shot
				const { newPassword } = req.body as { newPassword: string };
				if (!newPassword) {
					return res.status(400).json(standardResponse(false, "newPassword is required"));
				}
				const otpResult = await otpService.verifyOTP(email, otp, "forgotPassword", OTP_PREFIX);
				if (!otpResult.success || !otpResult.userId) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}
				const emailHash = hashEmail(email);
				const user = await storeModel.getUser(clientId, emailHash);
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}
				const isReused = await clientUserUtils.isPasswordReused(newPassword, user.lastPassword);
				if (isReused) {
					return res.status(400).json(standardResponse(false, "New password cannot be the same as your last password"));
				}
				const newHash = await clientUserUtils.hashPassword(newPassword);
				const now = new Date();
				await storeModel.findOneAndUpdate(
					{ clientId },
					{
						$set: {
							[`users.${emailHash}.lastPassword`]: user.passwordHash,
							[`users.${emailHash}.passwordHash`]: newHash,
							[`users.${emailHash}.lastPasswordChangedAt`]: now,
							[`users.${emailHash}.updatedAt`]: now,
						},
					},
				);
				return res.status(200).json(standardResponse(true, "Password reset successfully. You can now login.", {
					userId: otpResult.userId,
					email,
				}));
			}

			case "ac-re": {
				// Verify OTP + restore account in one shot
				const otpResult = await otpService.verifyOTP(email, otp, "accountRecovery", OTP_PREFIX);
				if (!otpResult.success) {
					return res.status(400).json(standardResponse(false, otpResult.message));
				}
				const emailHash = hashEmail(email);
				const user = await storeModel.getUser(clientId, emailHash);
				if (!user) {
					return res.status(404).json(standardResponse(false, "User not found"));
				}
				if (!user.isDeleted) {
					return res.status(400).json(standardResponse(false, "Account is not scheduled for deletion"));
				}
				if (user.status === "active") {
					return res.status(400).json(standardResponse(false, "Account is already active"));
				}
				const updated = clientUserUtils.restore(user);
				updated.updatedAt = new Date();
				await storeModel.findOneAndUpdate(
					{ clientId },
					{ $set: { [`users.${emailHash}`]: updated } },
				);
				return res.status(200).json(standardResponse(true, "Account recovered successfully. You can now login."));
			}

			default:
				return res.status(403).json(standardResponse(false, "Invalid OTP purpose"));
		}
	} catch (error) {
		next(error);
	}
}

// ─── Resend OTP ───────────────────────────────────────────────────────────────

export async function resendOTPController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { email }: z.infer<typeof ResendOTPSchema> = req.body;
        const purpose = req.query.purpose;
        if (!purpose || typeof purpose !== "string") {
            return res.status(400).json(standardResponse(false, "OTP purpose is required"));
        }
		const clientId = req.apiOwnerId!;
		const emailHash = hashEmail(email);

		const user = await storeModel.getUser(clientId, emailHash);
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		const otp = generateOTP();
		const html = getOtpHTML(otp, "resendOtp");
		const mailSent = await sendVerificationEmail(
			process.env.GMAIL_USER_EMAIL as string,
			email,
			"Your OTP",
			html,
		);
		if (!mailSent) {
			return res.status(503).json(standardResponse(false, "Failed to send OTP email. Please try again later."));
		}

		const otpStored = await otpService.storeOTP(email, otp, purpose, user.userId, undefined, 600, OTP_PREFIX);
		if (!otpStored.success) {
			return res.status(503).json(standardResponse(false, otpStored.message || "Failed to store OTP. Please try again later."));
		}

		return res.status(200).json(standardResponse(true, "OTP resent successfully. Please check your email."));
	} catch (error) {
		next(error);
	}
}

// ─── Forgot Password — sends OTP only ────────────────────────────────────────

export async function forgotPasswordController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { email }: z.infer<typeof ForgotPasswordSchema> = req.body;
		const clientId = req.apiOwnerId!;
		const emailHash = hashEmail(email);

		const user = await storeModel.getUser(clientId, emailHash);
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		const otp = generateOTP();
		const html = getOtpHTML(otp, "resetPassword");
		const mailSent = await sendVerificationEmail(
			process.env.GMAIL_USER_EMAIL as string,
			email,
			"Reset your password",
			html,
		);
		if (!mailSent) {
			return res.status(503).json(standardResponse(false, "Failed to send reset email. Please try again later."));
		}

		const otpStored = await otpService.storeOTP(email, otp, "forgotPassword", user.userId, undefined, 600, OTP_PREFIX);
		if (!otpStored.success) {
			return res.status(503).json(standardResponse(false, otpStored.message || "Failed to store OTP. Please try again later."));
		}

		return res.status(200).json(standardResponse(true, "OTP sent to your email. Submit OTP + new password to /verify?purpose=fr-pa", { email }));
	} catch (error) {
		next(error);
	}
}

// ─── Update Password — authenticated, old + new password ─────────────────────

export async function updatePasswordController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { oldPassword, newPassword }: z.infer<typeof UpdatePasswordSchema> = req.body;
		const { userId } = req.body as { userId: string };
		const clientId = req.apiOwnerId!;

		const store = await storeModel.findStore(clientId);
		if (!store) {
			return res.status(404).json(standardResponse(false, "Store not found"));
		}

		const found = await findUserByIdInStore(store, userId);
		if (!found) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		const { emailHash, user } = found;

		if (!user.passwordHash) {
			return res.status(403).json(standardResponse(false, "Password login not available for this account"));
		}

		const isOldValid = await clientUserUtils.comparePassword(oldPassword, user.passwordHash);
		if (!isOldValid) {
			return res.status(401).json(standardResponse(false, "Current password is incorrect"));
		}

		const isReused = await clientUserUtils.isPasswordReused(newPassword, user.lastPassword);
		if (isReused) {
			return res.status(400).json(standardResponse(false, "New password cannot be the same as your last password"));
		}

		const newHash = await clientUserUtils.hashPassword(newPassword);
		const now = new Date();

		await storeModel.findOneAndUpdate(
			{ clientId },
			{
				$set: {
					[`users.${emailHash}.lastPassword`]: user.passwordHash,
					[`users.${emailHash}.passwordHash`]: newHash,
					[`users.${emailHash}.lastPasswordChangedAt`]: now,
					[`users.${emailHash}.updatedAt`]: now,
				},
			},
		);

		return res.status(200).json(standardResponse(true, "Password updated successfully"));
	} catch (error) {
		next(error);
	}
}

// ─── Update Username ──────────────────────────────────────────────────────────

export async function updateUsernameController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { newUsername }: z.infer<typeof UpdateUsernameSchema> = req.body;
		const { userId } = req.body as { userId: string };
		const clientId = req.apiOwnerId!;

		const store = await storeModel.findStore(clientId);
		if (!store) {
			return res.status(404).json(standardResponse(false, "Store not found"));
		}

		const found = await findUserByIdInStore(store, userId);
		if (!found) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		await storeModel.findOneAndUpdate(
			{ clientId },
			{
				$set: {
					[`users.${found.emailHash}.username`]: newUsername.toLowerCase(),
					[`users.${found.emailHash}.updatedAt`]: new Date(),
				},
			},
		);

		return res.status(200).json(standardResponse(true, "Username updated successfully"));
	} catch (error) {
		next(error);
	}
}

// ─── Update Email — sends OTP to new email, verified via ?purpose=ve-em-up ────

export async function updateEmailController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { password, newEmail }: z.infer<typeof UpdateEmailSchema> = req.body;
		const { userId } = req.body as { userId: string };
		const clientId = req.apiOwnerId!;
		const newEmailHash = hashEmail(newEmail);

		const alreadyTaken = await storeModel.userExists(clientId, newEmailHash);
		if (alreadyTaken) {
			return res.status(409).json(standardResponse(false, "Email already in use"));
		}

		const store = await storeModel.findStore(clientId);
		if (!store) {
			return res.status(404).json(standardResponse(false, "Store not found"));
		}

		const found = await findUserByIdInStore(store, userId);
		if (!found || !found.user.passwordHash) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		const isPasswordValid = await clientUserUtils.comparePassword(password, found.user.passwordHash);
		if (!isPasswordValid) {
			return res.status(401).json(standardResponse(false, "Invalid password"));
		}

		const otp = generateOTP();
		const html = getOtpHTML(otp, "verifyEmailUP");
		const mailSent = await sendVerificationEmail(
			process.env.GMAIL_USER_EMAIL as string,
			newEmail,
			"Verify your new email",
			html,
		);
		if (!mailSent) {
			return res.status(503).json(standardResponse(false, "Failed to send verification email. Please try again later."));
		}

		const otpStored = await otpService.storeOTP(newEmail, otp, "verifyEmailUP", userId, newEmail, 600, OTP_PREFIX);
		if (!otpStored.success) {
			return res.status(503).json(standardResponse(false, otpStored.message || "Failed to store OTP. Please try again later."));
		}

		return res.status(200).json(standardResponse(true, "OTP sent to new email. Complete verification via /verify?purpose=ve-em-up"));
	} catch (error) {
		next(error);
	}
}

// ─── Delete Account ───────────────────────────────────────────────────────────

export async function deleteAccountController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { email, password }: z.infer<typeof DeleteAccountSchema> = req.body;
		const clientId = req.apiOwnerId!;
		const emailHash = hashEmail(email);

		const user = await storeModel.getUser(clientId, emailHash);
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

		const updated = clientUserUtils.softDelete(user);
		updated.updatedAt = new Date();

		await storeModel.findOneAndUpdate(
			{ clientId },
			{ $set: { [`users.${emailHash}`]: updated } },
		);

		return res.status(200).json(standardResponse(true, "Account scheduled for deletion. You can recover it within 30 days."));
	} catch (error) {
		next(error);
	}
}

// ─── Recover Account — sends OTP only, verified via ?purpose=ac-re ────────────

export async function recoverAccountController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	storeModel: StoreModel,
) {
	try {
		const { email } = req.body as { email: string };
		const clientId = req.apiOwnerId!;
		const emailHash = hashEmail(email);

		const user = await storeModel.getUser(clientId, emailHash);
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		if (!user.isDeleted) {
			return res.status(400).json(standardResponse(false, "Account is not scheduled for deletion"));
		}

		const otp = generateOTP();
		const html = getOtpHTML(otp, "accountRecovery");
		const mailSent = await sendVerificationEmail(
			process.env.GMAIL_USER_EMAIL as string,
			email,
			"Recover your account",
			html,
		);
		if (!mailSent) {
			return res.status(503).json(standardResponse(false, "Failed to send recovery email. Please try again later."));
		}

		const otpStored = await otpService.storeOTP(email, otp, "accountRecovery", user.userId, undefined, 600, OTP_PREFIX);
		if (!otpStored.success) {
			return res.status(503).json(standardResponse(false, otpStored.message || "Failed to store OTP. Please try again later."));
		}

		return res.status(200).json(standardResponse(true, "OTP sent to your email. Verify via /verify?purpose=ac-re to complete recovery."));
	} catch (error) {
		next(error);
	}
}
