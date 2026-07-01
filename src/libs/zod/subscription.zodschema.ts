import * as z from "zod";

export const buySubscriptionSchema = z.object({
	subscriptionPlanDetails: z.object({
		planName: z.enum(["Free", "Basic", "Pro"]),
		price: z.number().int().nonnegative(),
		duration: z.number().int().positive(),
		autoRenewStatus: z.boolean(),
	}).refine(
		(data) => {
			const expected: Record<string, { price: number; duration: number }> = {
				Free:  { price: 0,  duration: 12 },
				Basic: { price: 5,  duration: 12 },
				Pro:   { price: 15, duration: 12 },
			};
			const plan = expected[data.planName];
			if (!plan) return false;
			return plan.price === data.price && plan.duration === data.duration;
		},
		{ message: "Price or duration does not match the selected plan" },
	),
});
