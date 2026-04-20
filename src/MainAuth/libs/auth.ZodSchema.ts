import * as z from "zod";

export const registerSchema = z.object({
	username: z.string().min(5, "Username must be at least 5 characters long"),
	email: z.email().min(15, "Email is required"),
	password: z.string().min(8, "Password must be at least 8 characters long"),
});

export const loginDeleteRecoverAccSchema = z.object({
	usernameORemail: z
		.email()
		.min(15, "Email is required")
		.or(z.string().min(5, "Username must be at least 5 characters long")),
	password: z.string().min(8, "Password must be at least 8 characters long"),
});

export const otpSchema = z.object({
	otp: z.string().min(6, "OTP must be 6 digits"),
});

export const updateDetailsSchema = z.object({
	fieldToUpdate: z
		.string()
		.min(5, "Field value must be at least 5 characters long"),
	newValue: z.string().min(8, "New value must be at least 8 characters long"),
	password: z.string().min(8, "Password must be at least 8 characters long"),
});





// Regex Pattern Validators

const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

const usernameRegex = /^[A-Za-z][A-Za-z0-9]{4,29}$/;

const passwordRegex =
	/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,64}$/;

export const emailSchema = z
	.email()
	.min(15, "Email is required")
	.regex(emailRegex, "Invalid email format");

export const usernameSchema = z
	.string()
	.min(5, "Username must be at least 5 characters long")
	.regex(
		usernameRegex,
		"Username must contain only alphanumeric characters and underscores",
	);

export const passwordSchema = z
	.string()
	.min(8, "Password must be at least 8 characters long")
	.regex(
		passwordRegex,
		"Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
	);
