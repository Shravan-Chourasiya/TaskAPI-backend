import type { Model } from "mongoose";

export type ApiKeyType = {
	userId: string;
	name: string;
	description?: string;
	keyHash: string;
	keyPrefix: string;
	keyHint: string;
	subscriptionType: "Free" | "Basic" | "Pro";
	scopes: string[];
	status: "active" | "revoked" | "expired" | "blacklisted";
	isRevoked: boolean;
	revokedAt?: Date;
	revokedReason?: string;
	isBlacklisted: boolean;
	blacklistedAt?: Date;
	blacklistedReason?: string;
	expiresAt?: Date;
	lastUsedAt?: Date;
	usageCount: number;
	rateLimit: {
		requestsPerMinute: number;
		requestsPerHour: number;
	};
	allowedIPs: string[];
	environment: "production" | "development" | "test";
	createdAt: Date;
	updatedAt: Date;

	// Virtual fields
	isExpired: boolean;
	isActive: boolean;
	daysUntilExpiry: number | null;

	// Instance methods
	revoke: (reason?: string) => Promise<void>;
	blacklist: (reason?: string) => Promise<void>;
	updateUsage: () => Promise<void>;
	verifyKey: (plainKey: string) => boolean;
	hasScope: (requiredScope: string) => boolean;
	isIPAllowed: (ip: string) => boolean;
};

export type ApiKeyStaticMethods = Model<ApiKeyType> & {
	findActiveKeys: (userId: string) => Promise<ApiKeyType[]>;
	revokeAllUserKeys: (userId: string, reason?: string) => Promise<void>;
};