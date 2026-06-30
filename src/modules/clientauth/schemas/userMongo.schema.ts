import mongoose from "mongoose";
import { USER_LIMITS } from "../../../constants.js";
import type {
	ClientUserDocument,
	ClientUserStaticMethods,
} from "../types/userMongo.type.js";
export { clientUserUtils } from "../utils/clientUserUtils.js";

// ─── Flat per-user schema (one document = one end-user) ───────────────────────

const clientUserSchema = new mongoose.Schema(
	{
		// ── Tenant identity ───────────────────────────────────────────────────────
		clientId: {
			type: String,
			required: [true, "Client ID is required"],
		},

		// ── User identity ─────────────────────────────────────────────────────────
		email: {
			type: String,
			required: true,
			lowercase: true,
			trim: true,
		},
		username: {
			type: String,
			trim: true,
			lowercase: true,
			minlength: USER_LIMITS.USERNAME_MIN_LENGTH,
			maxlength: USER_LIMITS.USERNAME_MAX_LENGTH,
			match: [
				/^[a-z0-9_]+$/,
				"Username can only contain lowercase letters, numbers, and underscores",
			],
		},

		// ── Auth ──────────────────────────────────────────────────────────────────
		passwordHash: { type: String, select: false },
		lastPassword: { type: String, select: false },
		lastPasswordChangedAt: Date,
		authProvider: {
			type: String,
			enum: ["email", "google", "github", "facebook", "apple"],
			default: "email",
		},
		authProviderId: String,
		emailVerified: { type: Boolean, default: false },
		verifiedAt: Date,

		// ── Profile ───────────────────────────────────────────────────────────────
		profile: {
			firstName: {
				type: String,
				trim: true,
				maxlength: USER_LIMITS.NAME_MAX_LENGTH,
			},
			lastName: {
				type: String,
				trim: true,
				maxlength: USER_LIMITS.NAME_MAX_LENGTH,
			},
			avatarUrl: String,
			bio: { type: String, maxlength: USER_LIMITS.BIO_MAX_LENGTH },
			dateOfBirth: Date,
			phoneNumber: {
				type: String,
				match: [/^\+?[1-9]\d{1,14}$/, "Invalid phone number format"],
			},
		},

		// ── Access control ────────────────────────────────────────────────────────
		role: {
			type: String,
			enum: ["admin", "moderator", "user"],
			default: "user",
		},
		status: {
			type: String,
			enum: ["active", "inactive", "suspended", "pending", "deleted", "blacklisted"],
			default: "pending",
		},

		// ── Security ──────────────────────────────────────────────────────────────
		twoFactorEnabled: { type: Boolean, default: false },
		twoFactorSecret: { type: String, select: false },
		lastLoginAt: Date,
		lastLoginIp: String,
		lastActiveAt: Date,
		failedLoginAttempts: { type: Number, default: 0 },
		accountLockedUntil: Date,
		lastFailedLoginAt: Date,

		// ── Soft delete ───────────────────────────────────────────────────────────
		isDeleted: { type: Boolean, default: false },
		deletedAt: Date,
		// TTL index on this field — MongoDB auto-purges the document when this date passes
		scheduledDeletionAt: Date,
		blackListReason: String,
		blackListedAt: Date,
	},
	{
		timestamps: true,
		collection: "client_users",
	},
);

// ─── Indexes ──────────────────────────────────────────────────────────────────

// Primary lookup: clientId + email — unique per tenant, used for register/login/OTP flows
clientUserSchema.index({ clientId: 1, email: 1 }, { unique: true });

// TTL: auto-purge soft-deleted users once scheduledDeletionAt is reached
// sparse: true so documents without this field are ignored by the TTL worker
clientUserSchema.index(
	{ scheduledDeletionAt: 1 },
	{ expireAfterSeconds: 0, sparse: true },
);

// Sparse index for lock queries — only indexes documents that have an active lock
clientUserSchema.index({ accountLockedUntil: 1 }, { sparse: true });

// ─── Static methods ───────────────────────────────────────────────────────────

clientUserSchema.statics.findByEmail = function (
	clientId: string,
	email: string,
) {
	return this.findOne({ clientId, email: email.toLowerCase().trim() });
};

clientUserSchema.statics.findByDocId = function (
	clientId: string,
	docId: string,
) {
	return this.findOne({ clientId, _id: docId });
};

clientUserSchema.statics.emailExists = async function (
	clientId: string,
	email: string,
): Promise<boolean> {
	const doc = await this.findOne(
		{ clientId, email: email.toLowerCase().trim() },
		{ _id: 1 },
	);
	return doc !== null;
};

// ─── Model factory ────────────────────────────────────────────────────────────

export function initClientUserModel(db: mongoose.Connection) {
	return db.model<ClientUserDocument, ClientUserStaticMethods>(
		"ClientUser",
		clientUserSchema,
	);
}
