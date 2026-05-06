import type { Model, Document } from "mongoose";

export type UserType = {
	username: string;
	email: string;
	passwordHash: string;
	status: "active" | "unverified" | "suspended" | "deleted";
	isVerified: boolean;
	verifiedAt: Date;
	verificationToken: string;
	verificationTokenExpiry: Date;
	lastPassword: string;
	lastPasswordChangedAt: Date;
	failedLoginAttempts: number;
	accountLockedUntil: Date;
	lastFailedLoginAt: Date;
	LastLoginAt: Date;
	loginCount: number;
	lastLoginDevice: {
		deviceIP: string;
		userAgent: string;
		deviceType: string;
		browser: string;
		os: string;
		deviceId: string;
	};
	activeSessions: number;
	laastActiveAt: Date;
	profile: {
		firstName: string;
		lastName: string;
		avatarUrl: string;
		bio: string;
		phone: string;
		phoneVerified: boolean;
		country: string;
	};
	roles: "user" | "admin" | "moderator" | "developer";
	isDeleted: boolean;
	deletedAt: Date;
	scheduledDeletionAt: Date;
	deletedBy: string;
	is2FAEnabled: boolean;
	twoFASecret: string;
	twoFA_Options: "email" | "sms" | "authenticator";
	isBlackListed: boolean;
	blackListReason: string;
	blackListedAt: Date;
};

// Instance methods interface
export interface UserInstanceMethods {
	comparePassword(candidatePassword: string): Promise<boolean>;
	isPasswordReused(newPassword: string): Promise<boolean>;
	incrementFailedLogin(): Promise<void>;
	resetFailedLogin(): Promise<void>;
	updateLoginActivity(ip: string, userAgent: string): Promise<void>;
	softDelete(deletedBy?: string): Promise<void>;
	restore(): Promise<void>;
	generateVerificationToken(): string;
}

// Static methods interface
export interface UserStaticMethods extends Model<UserType, object, UserInstanceMethods> {
	findActive(): Promise<UserDocument[]>;
	findByEmail(email: string): Promise<UserDocument | null>;
	findByUsername(username: string): Promise<UserDocument | null>;
	findByRole(role: string): Promise<UserDocument[]>;
	getStatistics(): Promise<{
		total: number;
		active: number;
		unverified: number;
		suspended: number;
		deleted: number;
	}>;
}

// Combined document type
export type UserDocument = Document<unknown, object, UserType> & UserType & UserInstanceMethods;
