import * as z from "zod";

export const buySubscriptionSchema = z.object({
    userId:z.string(),
    subscriptionPlanDetails:z.object({
        planName:z.enum(["Free", "Basic", "Pro"]),
        price:z.number(),
        duration:z.number(), // e.g., 12 months,36 months
        autoRenewStatus:z.boolean(), 
    })
})
