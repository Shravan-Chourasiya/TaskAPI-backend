import z from "zod";
import {
	emailSchema,
	passwordSchema,
	usernameSchema,
} from "./auth.zodschema.js";

export const adminModifyUserSchema = z.object({
	userNewData: z.object({
		email: z.string().email(),
		username: z.string().optional(),
		emailVerified: z.boolean(),
		verifiedAt: z.date().optional(),

		// Profile
		profile: z.object({
			firstName: z.string().optional(),
			lastName: z.string().optional(),
			avatarUrl: z.string().url().optional(),
			bio: z.string().optional(),
			dateOfBirth: z.date().optional(),
			phoneNumber: z.string().optional(),
		}),

		// Access control
		role: z.enum(["admin", "moderator", "user"]),
		status: z.enum([
			"active",
			"inactive",
			"suspended",
			"pending",
			"deleted",
			"blacklisted",
		]),

		// Security flags
		twoFactorEnabled: z.boolean(),
		failedLoginAttempts: z.number().int().nonnegative(),
		accountLockedUntil: z.date().optional(),
		lastFailedLoginAt: z.date().optional(),

		// Soft delete / blacklist
		isDeleted: z.boolean(),
		deletedAt: z.date().optional(),
		scheduledDeletionAt: z.date().optional(),
		blackListReason: z.string().optional(),
		blackListedAt: z.date().optional(),
	}),
});

export type AdminEditableClientUserDataType = z.infer<
	typeof adminModifyUserSchema.shape.userNewData
>;

export const adminAddNewUserSchema = z.object({
	newUserData: z.object({
		email: emailSchema,
		username: usernameSchema,
		password: passwordSchema,
		emailVerified: z.boolean(),
		verifiedAt: z.date().optional(),

		// Access control
		role: z.enum(["admin", "moderator", "user"]),
		status: z.enum([
			"active",
			"inactive",
			"suspended",
			"pending",
			"deleted",
			"blacklisted",
		]),
	}),
});
