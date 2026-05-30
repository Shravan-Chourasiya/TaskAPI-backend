import mongoose from "mongoose";
import type { SubscriptionType } from "../../../../types/mongo_models/subscription.type.js";
import { SUBSCRIPTION_CONSTANTS } from "../../../../constants.js";

const subscriptionSchema = new mongoose.Schema(
	{
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
		},

		subscriptionType: {
			type: String,
			enum: ["Free", "Basic", "Pro"],
			required: true,
		},
		subscriptionAmount: {
			type:Number,
			default: 0,
			required: true,
		},
		lastSubscribedAt: {
			type: Date,
			default: Date.now,
		},
		subscriptionStatus: {
			type: String,
			enum: ["Active", "Expired", "Cancelled", "Suspended","Pending"],
			default: "Pending",
		},
		subscriptionEndDate: {
			type: Date,
		},
		subscriptionDurationMonths: {
			type: Number,
			default: 1,
		},
		paymentStatus: {
			type: String,
			enum: ["Completed", "Failed", "Pending"],
			default: "Pending",
		},
		paymentMethod: {
			type: String,
			enum: ["card", "netbanking", "wallet", "upi"],
			required: false,
		},
		autoRenew: {
			type: Boolean,
			default: false,
		},
		transactionId: {
			type: String,
			required: true,
			unique: true,
		},
		transactionHistory: {
			type: [
				{
					transactionId: { type: String, required: true },
					razorPayID: { type: String, required: true },
					amount: { type: Number, required: true },
					date: { type: Date, required: true },
					paymentMethod: {
						type: String,
						enum: ["card", "netbanking", "wallet", "upi"],
					},
					paymentStatus: { type: String, enum: ["Completed", "Failed", "Pending"] },
				},
			],
			default: [],
			required: true,
			limit: 25,
		},
	},
	{ timestamps: true },
);

subscriptionSchema.pre("save", function () {
	if (this.isNew && !this.subscriptionEndDate) {
		this.subscriptionEndDate = new Date(
			this.lastSubscribedAt.getTime() +
				this.subscriptionDurationMonths * SUBSCRIPTION_CONSTANTS.DAYS_PER_MONTH * 24 * 60 * 60 * 1000,
		);
	}
});

subscriptionSchema.index({ userId: 1 });
subscriptionSchema.index({ subscriptionStatus: 1, subscriptionEndDate: 1 });
subscriptionSchema.index({ "transactionHistory.transactionId": 1 });


// In subscription.model.ts - comparePlans method
subscriptionSchema.methods.comparePlans = function (
	targetPlan: "Free" | "Basic" | "Pro",
): boolean {
	const planLevel: { [key: string]: number } = { Free: 1, Basic: 2, Pro: 3 };
	const currentPlanName = this.subscriptionType; // ✅ Fixed
	const currentLevel = planLevel[currentPlanName];
	const targetLevel = planLevel[targetPlan];
	if (currentLevel === undefined || targetLevel === undefined) {
		return false;
	}
	return currentLevel < targetLevel;
};

subscriptionSchema.set("toJSON", { virtuals: true });
subscriptionSchema.set("toObject", { virtuals: true });

export const SubscriptionModel = mongoose.model<SubscriptionType>(
	"Subscription",
	subscriptionSchema,
);
