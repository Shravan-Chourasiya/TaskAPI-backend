import mongoose from "mongoose";
import type {
	UserType,
	UserStaticMethods,
} from "../../../Types/mongo_models/user.type.js";
import crypto from "crypto";
import bcrypt from "bcryptjs";

export const userSchema = new mongoose.Schema(
	{
		username: {
			type: String,
			required: [true, "Username is required"],
			unique: true,
			trim: true,
			lowercase: true,
			minlength: [3, "Username must be at least 3 characters"],
			maxlength: [40, "Username cannot exceed 40 characters"],
			match: [
				/^[a-z0-9_-]+$/,
				"Username can only contain lowercase letters, numbers, hyphens, and underscores",
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
			minlength: [8, "Password must be at least 8 characters"],
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
			max: [10, "Too many failed login attempts"],
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
						unique: true, // Index for efficient querying of devices
					},
				},
			],
			select: false,
			default: [],
		},

		activeSessions: {
			type: Number,
			default: 0,
			max: [5, "Cannot have more than 5 concurrent devices"],
		},

		lastActiveAt: {
			type: Date,
		},

		profile: {
			firstName: {
				type: String,
				trim: true,
				maxlength: [50, "First name cannot exceed 50 characters"],
			},
			lastName: {
				type: String,
				trim: true,
				maxlength: [50, "Last name cannot exceed 50 characters"],
			},
			avatarUrl: String,
			bio: {
				type: String,
				maxlength: [500, "Bio cannot exceed 500 characters"],
			},
			phone: {
				type: String,
				match: [/^\+?[1-9]\d{1,14}$/, "Invalid phone number format"],
			},
			phoneVerified: {
				type: Boolean,
				default: false,
			},
			country: {
				type: String,
				trim: true,
				maxlength: [100, "Country name cannot exceed 100 characters"],
			},
		},

		roles: {
			type: [String],
			enum: ["user", "admin", "moderator", "developer"],
			default: ["user"],
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
			default: ["email"],
			select: false,
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
userSchema.index({ email: 1, "lastLoginDevice.deviceId": 1 });

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

	this.passwordHash = await bcrypt.hash(this.passwordHash, 12);
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
		this.scheduledDeletionAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
		this.status = "deleted";
	}
});

// ============ INSTANCE METHODS ============
// Compare password
userSchema.methods.comparePassword = async function (
	candidatePassword: string,
): Promise<boolean> {
	return bcrypt.compare(candidatePassword, this.passwordHash);
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
	if (this.failedLoginAttempts >= 5) {
		this.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
	}

	// Lock account for 1 hour after 10 attempts
	if (this.failedLoginAttempts >= 10) {
		this.accountLockedUntil = new Date(Date.now() + 60 * 60 * 1000);
	}

	// Suspend account after 15 attempts
	if (this.failedLoginAttempts >= 15) {
		this.status = "suspended";
		this.accountLockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
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
	this.activeSessions += 1;

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
	this.scheduledDeletionAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
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
	return this.find({ roles: role, isDeleted: false });
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

const userModel = mongoose.model<UserType, UserStaticMethods>(
	"Users",
	userSchema,
);

export default userModel;
