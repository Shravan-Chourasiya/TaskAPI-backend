import z from "zod";

export const userActionSchema = z.object({
	action: z.enum(["suspend", "blacklist", "delete"]),
	reason: z.string().optional(),
});

export const modifySubscriptionSchema = z.object({
	subscriptionType: z.enum(["Free", "Basic", "Pro"]),
	subscriptionStatus: z.enum(["Active", "Expired", "Cancelled", "Suspended", "Pending"]),
	subscriptionEndDate: z.coerce.date(),
});
