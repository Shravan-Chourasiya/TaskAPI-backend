import * as z from "zod";

// Regex patterns
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const usernameRegex = /^[A-Za-z][A-Za-z0-9]{4,29}$/;
const passwordRegex =
	/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,64}$/;

// Base schemas
export const emailSchema = z
	.string()
	.email("Invalid email format")
	.min(5, "Email too short")
	.max(100, "Email too long")
	.regex(emailRegex, "Invalid email format");

export const usernameSchema = z
	.string()
	.min(5, "Username must be at least 5 characters")
	.max(30, "Username too long")
	.regex(
		usernameRegex,
		"Username must start with letter and contain only alphanumeric characters",
	);

export const passwordSchema = z
	.string()
	.min(8, "Password must be at least 8 characters")
	.max(128, "Password too long")
	.regex(
		passwordRegex,
		"Password must contain uppercase, lowercase, number, and special character",
	);

export const profileSchema = z.object({
	firstName:z.string().max(50, "First name too long").optional(),
	lastName: z.string().max(50, "Last name too long").optional(),
	bio: z.string().max(160, "Bio too long").optional(),
	avatarUrl: z.string().url("Invalid URL format").optional(),
	phone: z.e164().regex(/^\+?[1-9]\d{1,14}$/, "Invalid phone number format").optional(),
	country: z.string().max(100, "Country name too long").optional(),
});

// Register schema
export const registerSchema = z.object({
	username: usernameSchema,
	email: emailSchema,
	password: passwordSchema,
});

// Login/Delete/Recover schema
export const loginDeleteRecoverAccSchema = z.object({
	email: emailSchema,
	password: passwordSchema,
});

// OTP schema
export const otpSchema = z.object({
	otp: z
		.string()
		.length(6, "OTP must be exactly 6 digits")
		.regex(/^\d{6}$/, "OTP must contain only digits"),

		email: emailSchema,	
	});

// Update details schema
export const updateDetailsSchema = z
	.object({
		fieldToUpdate: z.enum(["username","profile", "email", "password", "profile"]),
		newValue: z.string().min(5, "New value required"),
		password: passwordSchema,
	})
	.refine(
		(data) => {
			// Validate newValue based on fieldToUpdate
			if (data.fieldToUpdate === "username") {
				return usernameSchema.safeParse(data.newValue).success;
			}
			if (data.fieldToUpdate === "email") {
				return emailSchema.safeParse(data.newValue).success;
			}
			if (data.fieldToUpdate === "password") {
				return passwordSchema.safeParse(data.newValue).success;
			}
			if (data.fieldToUpdate === "profile") {
				return profileSchema.safeParse(data.newValue).success;
			}
			return false;
		},
		{
			message: "New value doesn't match the field requirements",
			path: ["newValue"],
		},
	);

// Resend OTP schema
export const otpResendSchema = z.object({
	email: emailSchema,
});
