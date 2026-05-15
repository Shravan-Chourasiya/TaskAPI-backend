import mongoose from "mongoose";
import type { SubscriptionType } from "../../../../Types/mongo_models/subscription.type.js";

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
			default: "Free",
		},
		lastSubscribedAt: {
			type: Date,
			default: Date.now,
		},
		subscriptionStatus: {
			type: String,
			enum: ["Active", "Expired", "Cancelled", "Suspended"],
			default: "Active",
		},
		subscriptionEndDate: {
			type: Date,
		},
		subscriptionDurationMonths: {
			type: Number,
			default: 1,
		},
		paymentMethod: {
			type: String,
			enum: [
				"creditCard",
				"payPal",
				"bankTransfer",
				"upiId",
				"upiApp",
				"paytm",
			],
			required: false,
		},
		lastTransactionId: {
			type: String,
			default: null,
		},
		autoRenew: {
			type: Boolean,
			default: false,
		},
		transactionHistory: {
			type: [
				{
					transactionId: { type: String, required: true },
					paymentId: { type: String, required: true },
					amount: { type: Number, required: true },
					date: { type: Date, required: true },
					paymentMethod: {
						type: String,
						enum: [
							"creditCard",
							"payPal",
							"bankTransfer",
							"upiId",
							"upiApp",
							"paytm",
						],
					},
					status: { type: String, enum: ["Completed", "Failed", "Pending"] },
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
				this.subscriptionDurationMonths * 28 * 24 * 60 * 60 * 1000,
		);
	}
});

subscriptionSchema.index({ userId: 1 }, { unique: true });
subscriptionSchema.index({ subscriptionStatus: 1, subscriptionEndDate: 1 });
subscriptionSchema.index({ "transactionHistory.transactionId": 1 });

subscriptionSchema.virtual("isSubscriptionActive").get(function () {
	return {
		isActive:
			this.subscriptionStatus === "Active" && this.subscriptionEndDate
				? new Date() < this.subscriptionEndDate
				: false,
		endDate: this.subscriptionEndDate,
	};
});

subscriptionSchema.methods.comparePlans = function (
	targetPlan:"Free" | "Basic" | "Pro",
): boolean {
	const planLevel: { [key: string]: number } = { Free: 1, Basic: 2, Pro: 3 };
	const currentLevel = planLevel[this.subscriptionType];
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
