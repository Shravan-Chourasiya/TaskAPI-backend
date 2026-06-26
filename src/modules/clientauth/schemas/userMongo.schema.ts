import mongoose from "mongoose";
import { USER_LIMITS } from "../../../constants.js";
import type {
	ClientUsersStoreType,
	ClientUsersStoreDocument,
	ClientUsersStoreStaticMethods,
	ClientUser,
} from "../types/userMongo.type.js";
export { hashEmail, clientUserUtils } from "../utils/clientUserUtils.js";

// ─── Embedded user schema (used as Map value type definition only) ─────────────

const clientUserSubSchema = new mongoose.Schema(
	{
		userId: { type: String, required: true },
		email: { type: String, required: true, lowercase: true, trim: true },
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
		role: {
			type: String,
			enum: ["admin", "moderator", "user"],
			default: "user",
		},
		status: {
			type: String,
			enum: [
				"active",
				"inactive",
				"suspended",
				"pending",
				"deleted",
				"blacklisted",
			],
			default: "pending",
		},
		twoFactorEnabled: { type: Boolean, default: false },
		twoFactorSecret: { type: String, select: false },
		lastLoginAt: Date,
		lastLoginIp: String,
		lastActiveAt: Date,
		failedLoginAttempts: { type: Number, default: 0 },
		accountLockedUntil: Date,
		lastFailedLoginAt: Date,
		isDeleted: { type: Boolean, default: false },
		deletedAt: Date,
		scheduledDeletionAt: Date,
		blackListReason: String,
		blackListedAt: Date,
	},
	{ _id: false, timestamps: true },
);

// ─── Top-level schema (one document per TaskAPI client) ───────────────────────

const clientUsersStoreSchema = new mongoose.Schema(
	{
		clientId: {
			type: String,
			required: [true, "Client ID is required"],
			unique: true,
			index: true,
		},
		userCount: {
			type: Number,
			default: 0,
		},
		users: {
			type: Map,
			of: clientUserSubSchema,
			default: {},
		},
	},
	{
		timestamps: true,
		collection: "client_users_store",
	},
);

// ─── Static Methods ───────────────────────────────────────────────────────────

clientUsersStoreSchema.statics.findStore = function (clientId: string) {
	return this.findOne({ clientId });
};

clientUsersStoreSchema.statics.getUser = async function (
	clientId: string,
	emailHash: string,
): Promise<ClientUser | null> {
	const store = await this.findOne({ clientId }, { [`users.${emailHash}`]: 1 });
	return store?.users?.get(emailHash) ?? null;
};

clientUsersStoreSchema.statics.userExists = async function (
	clientId: string,
	emailHash: string,
): Promise<boolean> {
	const count = await this.countDocuments({
		clientId,
		[`users.${emailHash}`]: { $exists: true },
	});
	return count > 0;
};

// ─── Model Factory ────────────────────────────────────────────────────────────

export function initClientUsersStoreModel(db: mongoose.Connection) {
	return db.model<ClientUsersStoreDocument, ClientUsersStoreStaticMethods>(
		"ClientUsersStore",
		clientUsersStoreSchema,
	);
}
