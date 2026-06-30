import * as z from "zod";

// ─── Primitives ───────────────────────────────────────────────────────────────

export const usernameSchema = z
	.string()
	.min(3)
	.max(30)
	.regex(
		/^[a-z0-9_]+$/,
		"Username can only contain lowercase letters, numbers, and underscores.",
	);

export const emailSchema = z
	.string()
	.email("Please provide a valid email address.");

export const passwordSchema = z
	.string()
	.min(8)
	.max(100)
	.regex(
		/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
		"Password must contain at least one uppercase letter, one lowercase letter, and one number.",
	);

export const otpSchema = z
	.string()
	.length(6, "OTP must be exactly 6 digits")
	.regex(/^\d{6}$/, "OTP must be numeric");

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const RegisterSchema = z.object({
	username: usernameSchema,
	email: emailSchema,
	password: passwordSchema,
});

export const LoginSchema = z.object({
	email: emailSchema,
	password: passwordSchema,
});

export const LogoutSchema = z.object({
	deviceId: z.string().uuid("Invalid device ID format").optional(),
});

// ─── OTP — purpose-specific schemas ──────────────────────────────────────────

// ?purpose=ve-em-or — verify email on registration, activates account
export const VerifyEmailOnRegisterSchema = z.object({
	email: emailSchema,
	otp: otpSchema,
});

// ?purpose=ve-em-cu — step 1 of email update: verify OTP sent to CURRENT email
// confirms the real user (not a hacker with a stolen token) initiated the change
export const VerifyCurrentEmailSchema = z.object({
	docId: z.string().min(1, "docId is required"),
	otp: otpSchema,
	newEmail: emailSchema,   // passed through so step 2 knows where to send next OTP
});

// ?purpose=ve-em-up — step 2 of email update: verify OTP sent to NEW email, commits the change
export const VerifyNewEmailSchema = z.object({
	newEmail: emailSchema,
	otp: otpSchema,
});

// ?purpose=fr-pa — verify forgot-password OTP + submit new password in one shot
export const VerifyForgotPasswordSchema = z.object({
	email: emailSchema,
	otp: otpSchema,
	newPassword: passwordSchema,
});

// ?purpose=up-pa — authenticated user verifies OTP then submits new password
export const VerifyUpdatePasswordSchema = z.object({
	docId: z.string().min(1, "docId is required"),
	otp: otpSchema,
	newPassword: passwordSchema,
});

// ?purpose=ac-re — verify account recovery OTP, restores soft-deleted account
export const VerifyAccountRecoverySchema = z.object({
	email: emailSchema,
	otp: otpSchema,
});

// Resend OTP — generic, purpose comes from ?purpose= query param
export const ResendOTPSchema = z.object({
	email: emailSchema,
});

// ─── Password ─────────────────────────────────────────────────────────────────

// Authenticated user initiating password update — only old password needed to verify identity
// new password is submitted later via verifyOTPController ?purpose=up-pa
export const UpdatePasswordSchema = z.object({
	oldPassword: passwordSchema,
});

// Unauthenticated user who forgot password — sends OTP only
export const ForgotPasswordSchema = z.object({
	email: emailSchema,
});

// ─── Account updates ──────────────────────────────────────────────────────────

// Current username comes from session/token, only new one needed in body
export const UpdateUsernameSchema = z.object({
	newUsername: usernameSchema,
});

// Initiates email update — password confirm + new email, OTP sent to new email
export const UpdateEmailSchema = z.object({
	password: passwordSchema,
	newEmail: emailSchema,
});

// Soft-delete account — requires password confirmation
export const DeleteAccountSchema = z.object({
	password: passwordSchema,
});

// Recover soft-deleted account — sends OTP only
export const RecoverAccountSchema = z.object({
	email: emailSchema,
});
