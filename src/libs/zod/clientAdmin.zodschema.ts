import z from "zod";
import {
	emailSchema,
	passwordSchema,
	usernameSchema,
} from "./auth.zodschema.js";

// Partial patch — every field optional so an admin can edit a subset without
// resending the full current user object (fetch-then-merge on the client).
export const adminModifyUserSchema = z.object({
	userNewData: z.object({
		email: z.string().email().optional(),
		username: z.string().optional(),
		emailVerified: z.boolean().optional(),
		verifiedAt: z.date().optional(),

		// Profile
		profile: z.object({
			firstName: z.string().optional(),
			lastName: z.string().optional(),
			avatarUrl: z.string().url().optional(),
			bio: z.string().optional(),
			dateOfBirth: z.date().optional(),
			phoneNumber: z.string().optional(),
		}).optional(),

		// Access control
		role: z.enum(["admin", "moderator", "user"]).optional(),
		status: z.enum([
			"active",
			"inactive",
			"suspended",
			"pending",
			"deleted",
			"blacklisted",
		]).optional(),

		// Security flags
		twoFactorEnabled: z.boolean().optional(),
		failedLoginAttempts: z.number().int().nonnegative().optional(),
		accountLockedUntil: z.date().optional(),
		lastFailedLoginAt: z.date().optional(),

		// Soft delete / blacklist
		isDeleted: z.boolean().optional(),
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
