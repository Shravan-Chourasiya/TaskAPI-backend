import * as z from "zod";

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

// ─── Auth Schemas ─────────────────────────────────────────────────────────────

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

// ─── OTP Schemas ──────────────────────────────────────────────────────────────

export const VerifyOTPSchema = z.object({
	email: emailSchema,
	otp: z.string().length(6, "OTP must be exactly 6 digits").regex(/^\d{6}$/, "OTP must be numeric"),
});

export const ResendOTPSchema = z.object({
	email: emailSchema,
});

// ─── Password Schemas ─────────────────────────────────────────────────────────

// Authenticated user changing their own password (knows old password)
export const UpdatePasswordSchema = z.object({
	oldPassword: passwordSchema,
	newPassword: passwordSchema,
}).refine((data) => data.oldPassword !== data.newPassword, {
	message: "New password must be different from old password",
	path: ["newPassword"],
});

// Unauthenticated user who forgot password (OTP verified separately)
export const ForgotPasswordSchema = z.object({
	email: emailSchema,
});

export const ResetPasswordSchema = z.object({
	email: emailSchema,
	newPassword: passwordSchema,
});

// ─── Account Update Schemas ───────────────────────────────────────────────────

// Current username comes from session, only new one needed
export const UpdateUsernameSchema = z.object({
	newUsername: usernameSchema,
});

export const UpdateEmailSchema = z.object({
	password: passwordSchema,
	newEmail: emailSchema,
});

export const DeleteAccountSchema = z.object({
	email: emailSchema,
	password: passwordSchema,
});
