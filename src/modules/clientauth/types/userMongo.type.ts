import type mongoose from "mongoose";

// ─── Embedded User Object (stored as map value) ───────────────────────────────

export type ClientUser = {
	userId: string;                    // uuid generated on registration
	email: string;
	username?: string;
	passwordHash?: string;
	lastPassword?: string;
	lastPasswordChangedAt?: Date;
	authProvider: "email" | "google" | "github" | "facebook" | "apple";
	authProviderId?: string;
	emailVerified: boolean;
	verifiedAt?: Date;
	profile: {
		firstName?: string;
		lastName?: string;
		avatarUrl?: string;
		bio?: string;
		dateOfBirth?: Date;
		phoneNumber?: string;
	};
	role: "admin" | "moderator" | "user";
	status: "active" | "inactive" | "suspended" | "pending" | "deleted" | "blacklisted";
	twoFactorEnabled: boolean;
	twoFactorSecret?: string;
	lastLoginAt?: Date;
	lastLoginIp?: string;
	lastActiveAt?: Date;
	failedLoginAttempts: number;
	accountLockedUntil?: Date;
	lastFailedLoginAt?: Date;
	isDeleted: boolean;
	deletedAt?: Date;
	scheduledDeletionAt?: Date;
	blackListReason?: string;
	blackListedAt?: Date;
	createdAt: Date;
	updatedAt: Date;
};

// ─── Top-level Document (one per TaskAPI client) ──────────────────────────────

export type ClientUsersStoreType = {
	clientId: string;                    // TaskAPI userId of the API key owner
	userCount: number;                   // tracked to enforce plan limits
	users: Map<string, ClientUser>;   // key = sha256(email).slice(0,16)
};

// ─── Static Methods ───────────────────────────────────────────────────────────

export interface ClientUsersStoreStaticMethods extends mongoose.Model<ClientUsersStoreType> {
	findStore(clientId: string): Promise<ClientUsersStoreDocument | null>;
	getUser(clientId: string, emailHash: string): Promise<ClientUser | null>;
	userExists(clientId: string, emailHash: string): Promise<boolean>;
}

export type ClientUsersStoreDocument =
	mongoose.Document<mongoose.Types.ObjectId, object, ClientUsersStoreType> &
	ClientUsersStoreType;
