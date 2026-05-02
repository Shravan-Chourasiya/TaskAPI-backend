import { sessionSchema } from "./session.schema.js";

// ============ INDEXES ============
sessionSchema.index({ userId: 1, deviceId: 1 });
sessionSchema.index({ userId: 1, tokenFamily: 1 });
sessionSchema.index({ deviceId: 1, isRevoked: 1 });
sessionSchema.index({ deviceId: 1, tokenFamily: 1 });
sessionSchema.index({ userId: 1, lastActivityAt: 1 });

// TTL Index for expired refresh tokens
sessionSchema.index(
	{ refreshTokenExpiresAt: 1 },
	{
		expireAfterSeconds: 0,
		partialFilterExpression: { status: "expired" },
	},
);
sessionSchema.index(
	{ accessTokenExpiresAt: 1 },
	{
		expireAfterSeconds: 0,
		partialFilterExpression: { status: "expired" },
	},
);

// ============ VIRTUAL FIELDS ============
sessionSchema.virtual("isExpired").get(function () {
	return new Date() > this.refreshTokenExpiresAt;
});

sessionSchema.virtual("isActive").get(function () {
	return (
		this.status === "active" &&
		!this.isRevoked &&
		new Date() < this.refreshTokenExpiresAt
	);
});
