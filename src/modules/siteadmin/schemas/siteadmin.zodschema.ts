import z from "zod";

// ── API Key schemas ────────────────────────────────────────────────────────────

export const adminCreateApiKeySchema = z.object({
	name: z.string().min(5).max(50),
	description: z.string().min(10).max(300).optional(),
	env: z.enum(["production", "development", "test"]),
	scopes: z.array(z.string().min(1)).min(1),
	allowedIPs: z.array(z.string()).default(["0.0.0.0"]).optional(),
});

export const adminModifyApiKeySchema = z.object({
	name: z.string().min(5).max(50).optional(),
	description: z.string().min(10).max(300).optional(),
	scopes: z.array(z.string().min(1)).min(1).optional(),
	allowedIPs: z.array(z.string()).optional(),
	keyStatus: z.enum(["active", "revoked", "expired", "blacklisted"]).optional(),
}).refine((d) => Object.keys(d).length > 0, { message: "At least one field must be provided" });

export const apiKeyReasonSchema = z.object({
	reason: z.string().max(300).optional(),
});

// ── Subscription schemas ───────────────────────────────────────────────────────

export const adminCreateSubscriptionSchema = z.object({
	subscriptionType: z.enum(["Free", "Basic", "Pro"]),
	subscriptionStatus: z.enum(["Active", "Expired", "Cancelled", "Suspended", "Pending"]),
	subscriptionEndDate: z.coerce.date(),
});

export const extendTrialSchema = z.object({
	days: z.number().int().positive(),
});

export const changeSubscriptionTierSchema = z.object({
	subscriptionType: z.enum(["Free", "Basic", "Pro"]),
});

// ── User schemas ───────────────────────────────────────────────────────────────

export const adminCreateUserSchema = z.object({
	username: z.string().min(3).max(40),
	email: z.string().email(),
	password: z.string().min(8),
	role: z.enum(["user", "developer", "moderator", "admin"]).optional(),
});

export const adminModifyUserSchema = z.object({
	username: z.string().min(3).max(40).optional(),
	email: z.string().email().optional(),
	phone: z.string().optional(),
	profile: z.object({
		firstName: z.string().max(50).optional(),
		lastName: z.string().max(50).optional(),
		bio: z.string().max(500).optional(),
		country: z.string().optional(),
	}).optional(),
}).refine((d) => Object.keys(d).length > 0, { message: "At least one field must be provided" });

export const assignRoleSchema = z.object({
	role: z.enum(["user", "developer", "moderator", "admin"]),
});

// ── Metrics / report schemas ───────────────────────────────────────────────────

export const metricsQuerySchema = z.object({
	from: z.coerce.date().optional(),
	to: z.coerce.date().optional(),
	limit: z.coerce.number().int().positive().max(1000).default(100).optional(),
});

export const exportMetricsSchema = z.object({
	format: z.enum(["json", "csv"]).default("json"),
	from: z.coerce.date().optional(),
	to: z.coerce.date().optional(),
});

export const generateReportSchema = z.object({
	type: z.enum(["usage", "errors", "latency", "growth"]),
	from: z.coerce.date().optional(),
	to: z.coerce.date().optional(),
});
