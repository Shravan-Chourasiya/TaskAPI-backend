import bcrypt from "bcryptjs";
import { AUTH_CONSTANTS } from "../../../constants.js";
import type { ClientUser } from "../types/userMongo.type.js";

// Strip sensitive fields before returning user data to client
export const sanitizeUser = (user: ClientUser) => {
	const { passwordHash, lastPassword, twoFactorSecret, ...safe } = user;
	return safe;
};

// ─── User Utilities ───────────────────────────────────────────────────────────
// State transitions return atomic mongoose update patches ({ $set, $unset })
// so controllers persist them in a single findOneAndUpdate — no read-modify-write
// race and one source of truth per transition. The mutation helpers below
// (resetFailedLogin / updateLoginActivity / verifyEmail / softDelete / restore)
// remain for callers that already hold a document and want to mutate in place.

// Mongo update patch shape (subset of the operators used here)
export type UpdatePatch = {
	$set?: Record<string, unknown>;
	$unset?: Record<string, unknown>;
};

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

	// The one mutating helper the controllers still use (increment + lock escalation).
	incrementFailedLogin(user: ClientUser): ClientUser {
		user.failedLoginAttempts += 1;
		user.lastFailedLoginAt = new Date();

		if (user.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_PERM_LOCK) {
			user.status = "suspended";
			user.accountLockedUntil = new Date(Date.now() + AUTH_CONSTANTS.PERM_LOCK_DURATION_MS);
		} else if (user.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_TEMP_LOCK) {
			user.accountLockedUntil = new Date(Date.now() + AUTH_CONSTANTS.TEMP_LOCK_DURATION_MS);
		} else if (user.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_LOCK) {
			user.accountLockedUntil = new Date(Date.now() + AUTH_CONSTANTS.LOCK_DURATION_MS);
		}
		// below threshold — increment count only, no lock yet
		return user;
	},

	// Increment + (optional) lock escalation, returned as an atomic patch.
	// `user` is used for the current attempt count; the patch is $set-only so
	// it can be merged with other $set fields (e.g. lastFailedLoginAt).
	buildFailedLoginPatch(user: ClientUser): UpdatePatch {
		const updated = clientUserUtils.incrementFailedLogin(user);
		const $set: Record<string, unknown> = {
			failedLoginAttempts: updated.failedLoginAttempts,
			lastFailedLoginAt: updated.lastFailedLoginAt,
		};
		if (updated.accountLockedUntil) {
			$set.accountLockedUntil = updated.accountLockedUntil;
		}
		if (updated.status === "suspended") {
			$set.status = "suspended";
		}
		return { $set };
	},

	// Patch: set to active, bump login activity, clear failed-login/lock state.
	buildLoginSuccessPatch(ip: string): UpdatePatch {
		return {
			$set: {
				failedLoginAttempts: 0,
				lastLoginAt: new Date(),
				lastActiveAt: new Date(),
				lastLoginIp: ip,
			},
			$unset: { accountLockedUntil: "", lastFailedLoginAt: "" },
		};
	},

	// Patch: mark email verified and activate the account.
	buildVerifyEmailPatch(): UpdatePatch {
		return {
			$set: {
				emailVerified: true,
				verifiedAt: new Date(),
				status: "active",
			},
		};
	},

	// Patch: schedule deletion after the grace period; TTL index purges later.
	buildSoftDeletePatch(): UpdatePatch {
		return {
			$set: {
				isDeleted: true,
				deletedAt: new Date(),
				status: "deleted",
				scheduledDeletionAt: new Date(
					Date.now() + AUTH_CONSTANTS.SOFT_DELETE_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
				),
			},
		};
	},

	// Patch: restore a soft-deleted account, choosing status by verification.
	buildRestorePatch(emailVerified: boolean): UpdatePatch {
		return {
			$set: {
				isDeleted: false,
				status: emailVerified ? "active" : "pending",
			},
			$unset: { deletedAt: "", scheduledDeletionAt: "" },
		};
	},

	// Patch: rotate password, keeping the previous hash for reuse-checking.
	buildPasswordChangePatch(newHash: string, previousHash?: string): UpdatePatch {
		const $set: Record<string, unknown> = {
			passwordHash: newHash,
			lastPasswordChangedAt: new Date(),
		};
		if (previousHash) {
			$set.lastPassword = previousHash;
		}
		return { $set };
	},

	// Keep the mutating variants for external/legacy callers that hold a doc.
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
		clientId: string;
		email: string;
		passwordHash?: string;
		username?: string;
		authProvider?: ClientUser["authProvider"];
		authProviderId?: string;
	}): Omit<ClientUser, "createdAt" | "updatedAt"> {
		const user: Omit<ClientUser, "createdAt" | "updatedAt"> = {
			clientId: data.clientId,
			email: data.email.toLowerCase().trim(),
			authProvider: data.authProvider ?? "email",
			emailVerified: false,
			profile: {},
			role: "user",
			status: "pending",
			twoFactorEnabled: false,
			failedLoginAttempts: 0,
			isDeleted: false,
		};
		if (data.username) user.username = data.username.toLowerCase();
		if (data.passwordHash) user.passwordHash = data.passwordHash;
		if (data.authProviderId) user.authProviderId = data.authProviderId;
		return user;
	},
};
