import mongoose from "mongoose";
import type {
	ApiKeyType,
	ApiKeyStaticMethods,
} from "../../../types/mongo_models/apikeys.type.js";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { AUTH_CONSTANTS } from "../../../constants.js";

const apiKeySchema = new mongoose.Schema(
	{
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Users",
			required: true,
			index: true,
		},

		// Metadata
		name: {
			type: String,
			required: true,
			trim: true,
			maxlength: 100,
		},

		description: {
			type: String,
			trim: true,
			maxlength: 500,
		},

		// CRITICAL: Store only hashed key, never plaintext
		keyHash: {
			type: String,
			required: true,
			unique: true,
			select: false,
		},

		// Store prefix for identification (e.g., "sk_live_", "sk_test_")
		keyPrefix: {
			type: String,
			required: true,
			index: true,
		},

		// Last 4 characters for user identification
		keyHint: {
			type: String,
			required: true,
		},

		subscriptionType: {
			type: String,
			enum: ["Free", "Basic", "Pro"],
			required: true,
			index: true,
		},

		// Permissions & Scopes
		scopes: {
			type: [String],
			default: ["read"],
			enum: ["read", "write", "delete", "admin"],
		},

		// Status Fields
		keyStatus: {
			type: String,
			enum: ["active", "revoked", "expired", "blacklisted"],
			default: "active",
			index: true,
		},

		isRevoked: {
			type: Boolean,
			default: false,
			index: true,
		},

		revokedAt: Date,

		revokedReason: String,

		isBlacklisted: {
			type: Boolean,
			default: false,
			index: true,
		},

		blacklistedAt: Date,

		blacklistedReason: String,

		// Expiry
		expiresAt: {
			type: Date,
			index: true,
		},

		// Usage Tracking
		lastUsedAt: {
			type: Date,
			index: true,
		},

		usageCount: {
			type: Number,
			default: 0,
		},

		// Rate Limiting (requests per minute/hour)
		rateLimit: {
			requestsPerMinute: {
				type: Number,
				default: 60,
			},
			requestsPerHour: {
				type: Number,
				default: 1000,
			},
		},

		// IP Restrictions
		allowedIPs: {
			type: [String],
			default: [],
		},

		// Environment
		environment: {
			type: String,
			enum: ["production", "development", "test"],
			default: "production",
		},
	},
	{
		timestamps: true,
		collection: "apikeys",
	},
);

// ============ INDEXES ============
apiKeySchema.index({ userId: 1, keyStatus: 1 });
apiKeySchema.index({ userId: 1, isRevoked: 1, isBlacklisted: 1 });
apiKeySchema.index({ keyHash: 1, keyStatus: 1 });
apiKeySchema.index({ subscriptionType: 1, keyStatus: 1 });
apiKeySchema.index({ expiresAt: 1 }, { sparse: true });
apiKeySchema.index({ lastUsedAt: 1 });

// TTL Index for expired keys
apiKeySchema.index(
	{ expiresAt: 1 },
	{
		expireAfterSeconds: 0,
		partialFilterExpression: { keyStatus: "expired" },
	},
);

// ============ VIRTUAL FIELDS ============
apiKeySchema.virtual("isExpired").get(function () {
	return this.expiresAt ? new Date() > this.expiresAt : false;
});

apiKeySchema.virtual("isActive").get(function () {
	return this.keyStatus === "active" && !this.isRevoked && !this.isBlacklisted;
});

apiKeySchema.virtual("daysUntilExpiry").get(function () {
	if (!this.expiresAt) return null;
	const now = new Date();
	const diff = this.expiresAt.getTime() - now.getTime();
	return Math.ceil(diff / (1000 * 60 * 60 * 24));
});

// ============ MIDDLEWARE ============
apiKeySchema.pre("save", function () {
	if (this.isModified("isRevoked") && this.isRevoked) {
		this.keyStatus = "revoked";
		if (!this.revokedAt) {
			this.revokedAt = new Date();
		}
	}

	if (this.isModified("isBlacklisted") && this.isBlacklisted) {
		this.keyStatus = "blacklisted";
		if (!this.blacklistedAt) {
			this.blacklistedAt = new Date();
		}
	}

	if (this.expiresAt && new Date() > this.expiresAt) {
		this.keyStatus = "expired";
	}
});

apiKeySchema.pre("save", async function () {
	if (this.isModified("keyHash") && !this.keyHash.startsWith("$2")) {
		this.keyPrefix = this.keyHash.substring(0, 8);
		this.keyHint = this.keyHash.slice(-4);
		this.keyHash = await bcrypt.hash(
			this.keyHash,
			AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
		);
	}
});

// ============ INSTANCE METHODS ============
apiKeySchema.methods.revoke = async function (reason?: string): Promise<void> {
	this.isRevoked = true;
	this.keyStatus = "revoked";
	this.revokedAt = new Date();
	if (reason) {
		this.revokedReason = reason;
	}
	await this.save();
};

apiKeySchema.methods.blacklist = async function (
	reason?: string,
): Promise<void> {
	this.isBlacklisted = true;
	this.keyStatus = "blacklisted";
	this.blacklistedAt = new Date();
	if (reason) {
		this.blacklistedReason = reason;
	}
	await this.save();
};

apiKeySchema.methods.updateUsage = async function (): Promise<void> {
	this.lastUsedAt = new Date();
	this.usageCount += 1;
	await this.save();
};

apiKeySchema.methods.verifyKey = function (plainKey: string): boolean {
	const hash = bcrypt.compareSync(plainKey, this.keyHash);
	return hash;
};

apiKeySchema.methods.hasScope = function (requiredScope: string): boolean {
	return this.scopes.includes(requiredScope) || this.scopes.includes("admin");
};

apiKeySchema.methods.isIPAllowed = function (ip: string): boolean {
	if (this.allowedIPs.length === 0) return true;
	return this.allowedIPs.includes(ip);
};

// ============ STATIC METHODS ============

apiKeySchema.statics.findActiveKeys = function (userId: string) {
	return this.find({
		userId,
		keyStatus: "active",
		isRevoked: false,
		isBlacklisted: false,
	});
};

apiKeySchema.statics.revokeAllUserKeys = async function (
	userId: string,
	reason?: string,
): Promise<void> {
	await this.updateMany(
		{ userId, isRevoked: false },
		{
			isRevoked: true,
			keyStatus: "revoked",
			revokedAt: new Date(),
			revokedReason: reason,
		},
	);
};


apiKeySchema.set("toJSON", { virtuals: true });
apiKeySchema.set("toObject", { virtuals: true });

export const apiKeyModel = mongoose.model<ApiKeyType, ApiKeyStaticMethods>(
	"ApiKey",
	apiKeySchema,
);
