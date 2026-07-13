import type mongoose from "mongoose";

// ─── Flat per-user document type ──────────────────────────────────────────────

export type ClientUser = {
	// Tenant identity
	clientId: string;                  // apiOwnerId from API key middleware
	// User identity — _id (ObjectId) is the unique doc identity, no separate userId field
	email: string;
	username?: string;
	// Auth
	passwordHash?: string;
	lastPassword?: string;
	lastPasswordChangedAt?: Date;
	authProvider: "email" | "google" | "github" | "facebook" | "apple";
	authProviderId?: string;
	emailVerified: boolean;		
	verifiedAt?: Date;
	// Profile
	profile: {
		firstName?: string;
		lastName?: string;
		avatarUrl?: string;
		bio?: string;
		dateOfBirth?: Date;
		phoneNumber?: string;
	};
	// Access control
	role: "admin" | "moderator" | "user";
	status: "active" | "inactive" | "suspended" | "pending" | "deleted" | "blacklisted";
	// Security
	twoFactorEnabled: boolean;
	twoFactorSecret?: string;
	lastLoginAt?: Date;
	lastLoginIp?: string;
	lastActiveAt?: Date;
	failedLoginAttempts: number;
	accountLockedUntil?: Date;
	lastFailedLoginAt?: Date;
	// Soft delete
	isDeleted: boolean;
	deletedAt?: Date;
	scheduledDeletionAt?: Date;     // TTL index target — MongoDB purges doc when this passes
	blackListReason?: string;
	blackListedAt?: Date;
	// Timestamps (from mongoose { timestamps: true })
	createdAt: Date;
	updatedAt: Date;
};

// ─── Mongoose document type ───────────────────────────────────────────────────

export type ClientUserDocument =
	mongoose.Document<mongoose.Types.ObjectId, object, ClientUser> &
	ClientUser;

// ─── Static methods ───────────────────────────────────────────────────────────

export interface ClientUserStaticMethods extends mongoose.Model<ClientUser> {
	// Lookup by clientId + email (register, login, OTP flows)
	findByEmail(clientId: string, email: string): mongoose.Query<ClientUserDocument | null, ClientUserDocument>;
	// Lookup by clientId + _id (authenticated operations: update password, username, email, delete)
	findByDocId(clientId: string, docId: string): mongoose.Query<ClientUserDocument | null, ClientUserDocument>;
	// Existence check without loading the full document
	emailExists(clientId: string, email: string): Promise<boolean>;
}
