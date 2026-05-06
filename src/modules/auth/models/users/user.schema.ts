import mongoose from "mongoose";
import type { UserType, UserStaticMethods } from "../../../../Types/mongo_models/user.type.js";

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

		// Temporary fields until status is unverified for the user

		verificationToken: {
			type: String,
			select: false,
		},

		verificationTokenExpiry: {
			type: Date,
			select: false,
		},

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

// Import methods before creating model
import "./user.methods.js";

const userModel = mongoose.model<UserType, UserStaticMethods>("Users", userSchema);

export default userModel;
