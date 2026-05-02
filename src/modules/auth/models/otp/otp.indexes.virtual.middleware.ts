import { otpSchema } from "./otp.model.js";

// ============ INDEXES ============
otpSchema.index({ userId: 1, otpStatus: 1 });
otpSchema.index({ email: 1, otpStatus: 1 });
otpSchema.index({ userId: 1, isUsed: 1 });
otpSchema.index({ email: 1, isUsed: 1 });

// TTL Index for automatic cleanup of expired OTPs
otpSchema.index(
    { expiresAt: 1 },
    {
        expireAfterSeconds: 0,
        partialFilterExpression: { otpStatus: "expired" },
    },
);

// ============ VIRTUAL FIELDS ============
otpSchema.virtual("isExpired").get(function () {
    return new Date() > this.expiresAt;
});

otpSchema.virtual("isValid").get(function () {
    return (
        this.otpStatus === "pending" &&
        !this.isUsed &&
        this.attemptsLeft > 0 &&
        new Date() < this.expiresAt
    );
});


// ============ PRE-SAVE MIDDLEWARE ============
// Auto-set status to expired if past expiry time
otpSchema.pre("save", function (next) {
    if (new Date() > this.expiresAt && this.otpStatus === "pending") {
        this.otpStatus = "expired";
    }
    next;
});
