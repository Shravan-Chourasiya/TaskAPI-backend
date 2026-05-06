import bcrypt from "bcryptjs";
import { userSchema } from "./user.schema.js";

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
	if (!this.isModified("password")){ return ;};

	// Hash new password
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
	};
});
