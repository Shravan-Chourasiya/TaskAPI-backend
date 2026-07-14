import mongoose from "mongoose";
import type {
	UserDocument,
	UserType,
	UserStaticMethods,
} from "../../../types/mongoModels/user.type.js";
import * as crypto from "crypto";
import * as bcrypt from "bcryptjs";
import { AUTH_CONSTANTS, USER_LIMITS, ROLE_RANK, type UserRole } from "../../../constants.js";

export const userSchema = new mongoose.Schema(
	{
		username: {
			type: String,
			required: [true, "Username is required"],
			unique: true,
			trim: true,
			minlength: [
				USER_LIMITS.USERNAME_MIN_LENGTH,
				"Username must be at least 6 characters",
			],
			maxlength: [
				USER_LIMITS.USERNAME_MAX_LENGTH,
				"Username cannot exceed 40 characters",
			],
			match: [
				/^[A-Za-z0-9_-]+$/,
				"Username can only contain lowercase, uppercase letters, numbers, hyphens, and underscores",
			],
		},

		email: {
			type: String,
			required: [true, "Email is required"],
			unique: true,
			trim: true,
			lowercase: true,
			match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
			index: true,
		},

		passwordHash: {
			type: String,
			required: [true, "Password is required"],
			minlength: [
				USER_LIMITS.PASSWORD_MIN_LENGTH,
				"Password must be at least 8 characters",
			],
			select: false,
		},

		status: {
			type: String,
			enum: ["active", "unverified", "suspended", "deleted"],
			default: "unverified",
			index: true,
		},

		isVerified: {
			type: Boolean,
			default: false,
			index: true,
		},

		verifiedAt: Date,

		lastPassword: {
			type: String,
			select: false,
		},

		lastPasswordChangedAt: Date,

		failedLoginAttempts: {
			type: Number,
			default: 0,
			max: [
				AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_TEMP_LOCK,
				"Too many failed login attempts",
			],
		},

		accountLockedUntil: Date,

		lastFailedLoginAt: Date,

		lastLoginAt: Date,

		loginCount: {
			type: Number,
			default: 0,
		},

		lastLoginDevice: {
			type: [
				{
					deviceIP: String,
					userAgent: String,
					deviceType: String,
					browser: String,
					os: String,
					deviceId: {
						type: String,
					},
				},
			],
			select: false,
			default: [],
		},

		activeSessions: {
			type: Number,
			default: 0,
			max: [
				AUTH_CONSTANTS.MAX_ACTIVE_SESSIONS,
				"Cannot have more than 5 concurrent devices",
			],
		},

		sessionDevices: {
			type: [String],
			default: [],
			max: [
				AUTH_CONSTANTS.MAX_ACTIVE_SESSIONS,
				"Cannot have more than 5 concurrent devices",
			],
		},

		lastActiveAt: {
			type: Date,
		},

		profile: {
			firstName: {
				type: String,
				trim: true,
				maxlength: [
					USER_LIMITS.NAME_MAX_LENGTH,
					"First name cannot exceed 50 characters",
				],
			},
			lastName: {
				type: String,
				trim: true,
				maxlength: [
					USER_LIMITS.NAME_MAX_LENGTH,
					"Last name cannot exceed 50 characters",
				],
			},
			avatarUrl: String,
			bio: {
				type: String,
				maxlength: [
					USER_LIMITS.BIO_MAX_LENGTH,
					"Bio cannot exceed 500 characters",
				],
			},
			country: {
				type: String,
				trim: true,
				maxlength: [100, "Country name cannot exceed 100 characters"],
			},
		},

		phone: {
			type: String,
			match: [/^\+?[1-9]\d{1,14}$/, "Invalid phone number format"],
			default: "",
		},
		isPhoneVerified: {
			type: Boolean,
			default: false,
		},

		role: {
			type: String,
			enum: Object.keys(ROLE_RANK),
			default: "user" satisfies UserRole,
			index: true,
		},

		subscriptionType: {
			type: String,
			enum: ["Free", "Basic", "Pro"],
		},

		subscriptionExpiryDate: {
			type: Date,
		},

		apiKeyCount: {
			type: Number,
			default: 0,
			max: 26,
		},

		isDeleted: {
			type: Boolean,
			default: false,
			index: true,
		},

		deletedAt: Date,

		scheduledDeletionAt: {
			type: Date,
		},

		deletedBy: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Users",
		},

		is2FAEnabled: {
			type: Boolean,
			default: false,
			index: true,
		},

		twoFASecret: {
			type: String,
			select: false,
		},

		twoFA_Options: {
			type: [String],
			enum: ["email", "sms", "authenticator"],
			default: [],
			select: false,
		},

		twoFA_email: {
			type: String,
			match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
			default: "",
		},

		twoFA_emailVerified: {
			type: Boolean,
			default: false,
		},

		recoveryEmail: {
			type: String,
			match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
			default: "",
		},

		recoveryEmailVerified: {
			type: Boolean,
			default: false,
		},

		isBlackListed: {
			type: Boolean,
			default: false,
			index: true,
		},

		blackListReason: String,

		blackListedAt: Date,
	},
	{
		timestamps: true,
		collection: "users",
		toJSON: { virtuals: true },
		toObject: { virtuals: true },
	},
);

// Indexs for efficient querying
userSchema.index({ email: 1, status: 1 });
userSchema.index({ email: 1, isDeleted: 1 });
userSchema.index({ email: 1, isVerified: 1 });
userSchema.index({ email: 1, isBlackListed: 1 });
userSchema.index({ email: 1, is2FAEnabled: 1 });

// TTL Index for permanent deletion of soft-deleted accounts
userSchema.index(
	{ scheduledDeletionAt: 1 },
	{
		expireAfterSeconds: 0,
		partialFilterExpression: { isDeleted: true, status: "deleted" },
	},
);

// virtual fields : Calculated after a db Call in ram Creates runtime fields using db existing fields
userSchema.virtual("fullName").get(function () {
	const first = this.profile?.firstName || "";
	const last = this.profile?.lastName || "";
	return `${first} ${last}`.trim() || this.username;
});

userSchema.virtual("isLocked").get(function () {
	return !!(this.accountLockedUntil && this.accountLockedUntil > new Date());
});

userSchema.virtual("isActive").get(function () {
	return this.status === "active" && this.isVerified && !this.isDeleted;
});

userSchema.virtual("accountAge").get(function () {
	const now = new Date();
	const created = this.createdAt || now;
	return Math.floor(
		(now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24),
	);
});

// ============ MIDDLEWARE ============
// Pre-save: Hash password if modified
userSchema.pre("save", async function () {
	// Skip if already hashed or not modified
	if (!this.isModified("passwordHash") || this.passwordHash.startsWith("$2")) {
		return;
	}

	this.passwordHash = await bcrypt.hash(
		this.passwordHash,
		AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
	);
	this.lastPasswordChangedAt = new Date();
});

// Pre-save: Update verification status
userSchema.pre("save", function () {
	if (this.isModified("isVerified") && this.isVerified && !this.verifiedAt) {
		this.verifiedAt = new Date();
		this.status = "active";
	}
});

// Pre-save: Set scheduled deletion date
userSchema.pre("save", function () {
	if (
		this.isModified("isDeleted") &&
		this.isDeleted &&
		!this.scheduledDeletionAt
	) {
		this.deletedAt = new Date();
		this.scheduledDeletionAt = new Date(
			Date.now() +
				AUTH_CONSTANTS.SOFT_DELETE_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
		);
		this.status = "deleted";
	}
});

// ============ INSTANCE METHODS ============
// Compare password
userSchema.methods.comparePassword = async function (
	candidatePassword: string,
): Promise<boolean> {
	const result = await bcrypt.compare(candidatePassword, this.passwordHash);
	return result;
};

// Check if password was used before
userSchema.methods.isPasswordReused = async function (
	newPassword: string,
): Promise<boolean> {
	if (!this.lastPassword) {
		return false;
	}
	return bcrypt.compare(newPassword, this.lastPassword);
};

// Increment failed login attempts
userSchema.methods.incrementFailedLogin = async function (): Promise<void> {
	this.failedLoginAttempts += 1;
	this.lastFailedLoginAt = new Date();

	// Lock account after 5 failed attempts for 15 minutes
	if (this.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_LOCK) {
		this.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
	}

	// Lock account for 1 hour after 10 attempts
	if (
		this.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_TEMP_LOCK
	) {
		this.accountLockedUntil = new Date(Date.now() + 60 * 60 * 1000);
	}

	// Suspend account after 15 attempts
	if (
		this.failedLoginAttempts >= AUTH_CONSTANTS.FAILED_LOGIN_THRESHOLD_PERM_LOCK
	) {
		this.status = "suspended";
		this.accountLockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000);
	}

	await this.save();
};

// Reset failed login attempts
userSchema.methods.resetFailedLogin = async function (): Promise<void> {
	this.failedLoginAttempts = 0;
	this.accountLockedUntil = undefined;
	this.lastFailedLoginAt = undefined;
	await this.save();
};

// Update login activity
userSchema.methods.updateLoginActivity = async function (
	ip: string,
	userAgent: string,
): Promise<void> {
	this.lastLoginAt = new Date();
	this.lastActiveAt = new Date();
	this.loginCount += 1;

	if (!this.lastLoginDevice) {
		this.lastLoginDevice = [];
	}
	// Parse user agent (basic implementation)
	this.lastLoginDevice.push({
		userAgent,
		deviceType: /mobile/i.test(userAgent) ? "mobile" : "desktop",
		browser: userAgent.split("/")[0] || "unknown",
		os: /windows/i.test(userAgent)
			? "Windows"
			: /mac/i.test(userAgent)
				? "macOS"
				: /linux/i.test(userAgent)
					? "Linux"
					: "unknown",
		deviceId: crypto.randomBytes(16).toString("hex"),
	});

	await this.save();
};

// Soft delete account
userSchema.methods.softDelete = async function (
	deletedBy?: string,
): Promise<void> {
	this.isDeleted = true;
	this.deletedAt = new Date();
	this.status = "deleted";
	this.scheduledDeletionAt = new Date(
		Date.now() +
			AUTH_CONSTANTS.SOFT_DELETE_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
	);
	if (deletedBy) {
		this.deletedBy = deletedBy;
	}
	await this.save();
};

// Restore deleted account
userSchema.methods.restore = async function (): Promise<void> {
	this.isDeleted = false;
	this.deletedAt = undefined;
	this.scheduledDeletionAt = undefined;
	this.deletedBy = undefined;
	this.status = this.isVerified ? "active" : "unverified";
	await this.save();
};

// Generate verification token
userSchema.methods.generateVerificationToken = function (): string {
	const token = crypto.randomBytes(32).toString("hex");
	this.verificationToken = crypto
		.createHash("sha256")
		.update(token)
		.digest("hex");
	this.verificationTokenExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
	return token;
};

// ============ STATIC METHODS FOR ADMIN USE =============
// Find active users
userSchema.statics.findActive = function () {
	return this.find({ status: "active", isDeleted: false });
};

// Find by email (case-insensitive)
userSchema.statics.findByEmail = function (email: string) {
	return this.findOne({ email: email.toLowerCase(), isDeleted: false });
};

// Find by username (case-insensitive)
userSchema.statics.findByUsername = function (username: string) {
	return this.findOne({ username: username.toLowerCase(), isDeleted: false });
};

// Find users by role
userSchema.statics.findByRole = function (role: string) {
	return this.find({ role, isDeleted: false });
};

// Get user statistics
userSchema.statics.getStatistics = async function () {
	const [total, active, unverified, suspended, deleted] = await Promise.all([
		this.countDocuments({ isDeleted: false }),
		this.countDocuments({ status: "active", isDeleted: false }),
		this.countDocuments({ status: "unverified", isDeleted: false }),
		this.countDocuments({ status: "suspended", isDeleted: false }),
		this.countDocuments({ isDeleted: true }),
	]);

	return { total, active, unverified, suspended, deleted };
};

export function initUserModel(TaskapiDb: mongoose.Connection) {
	return TaskapiDb.model<UserDocument, UserStaticMethods>("Users", userSchema);
}
