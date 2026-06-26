import bcrypt from "bcryptjs";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { AUTH_CONSTANTS } from "../../../constants.js";
import type { ClientUser } from "../types/userMongo.type.js";

// ─── Email Hasher ─────────────────────────────────────────────────────────────

export const hashEmail = (email: string): string =>
	crypto
		.createHash("sha3-256")
		.update(email.toLowerCase().trim())
		.digest("hex")
		.slice(0, 32);

// ─── User Utilities ───────────────────────────────────────────────────────────

export const clientUserUtils = {
	async hashPassword(plainPassword: string): Promise<string> {
		return bcrypt.hash(plainPassword, AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS);
	},

	async comparePassword(plainPassword: string, passwordHash: string): Promise<boolean> {
		return bcrypt.compare(plainPassword, passwordHash);
	},

	async isPasswordReused(plainPassword: string, lastPasswordHash?: string): Promise<boolean> {
		if (!lastPasswordHash) return false;
		return bcrypt.compare(plainPassword, lastPasswordHash);
	},

	isLocked(user: ClientUser): boolean {
		return !!(user.accountLockedUntil && user.accountLockedUntil > new Date());
	},

	isActive(user: ClientUser): boolean {
		return user.status === "active" && user.emailVerified && !user.isDeleted;
	},

	incrementFailedLogin(user: ClientUser): ClientUser {
		user.failedLoginAttempts += 1;
		user.lastFailedLoginAt = new Date();

		if (user.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_LOCK) {
			user.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
		}
		if (user.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_TEMP_LOCK) {
			user.accountLockedUntil = new Date(Date.now() + 60 * 60 * 1000);
		}
		if (user.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_PERM_LOCK) {
			user.status = "suspended";
			user.accountLockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000);
		}
		return user;
	},

	resetFailedLogin(user: ClientUser): ClientUser {
		user.failedLoginAttempts = 0;
		delete user.accountLockedUntil;
		delete user.lastFailedLoginAt;
		return user;
	},

	updateLoginActivity(user: ClientUser, ip: string): ClientUser {
		user.lastLoginAt = new Date();
		user.lastActiveAt = new Date();
		user.lastLoginIp = ip;
		return user;
	},

	verifyEmail(user: ClientUser): ClientUser {
		user.emailVerified = true;
		user.verifiedAt = new Date();
		user.status = "active";
		return user;
	},

	softDelete(user: ClientUser): ClientUser {
		user.isDeleted = true;
		user.deletedAt = new Date();
		user.status = "deleted";
		user.scheduledDeletionAt = new Date(
			Date.now() + AUTH_CONSTANTS.SOFT_DELETE_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
		);
		return user;
	},

	restore(user: ClientUser): ClientUser {
		user.isDeleted = false;
		delete user.deletedAt;
		delete user.scheduledDeletionAt;
		user.status = user.emailVerified ? "active" : "pending";
		return user;
	},

	createNewUser(data: {
		email: string;
		passwordHash?: string;
		username?: string;
		authProvider?: ClientUser["authProvider"];
		authProviderId?: string;
	}): ClientUser {
		const now = new Date();
		const user: ClientUser = {
			userId: uuidv4(),
			email: data.email.toLowerCase(),
			authProvider: data.authProvider ?? "email",
			emailVerified: false,
			profile: {},
			role: "user",
			status: "pending",
			twoFactorEnabled: false,
			failedLoginAttempts: 0,
			isDeleted: false,
			createdAt: now,
			updatedAt: now,
		};
		if (data.username) user.username = data.username.toLowerCase();
		if (data.passwordHash) user.passwordHash = data.passwordHash;
		if (data.authProviderId) user.authProviderId = data.authProviderId;
		return user;
	},
};
