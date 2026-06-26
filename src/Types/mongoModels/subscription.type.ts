import type { Document, Model } from "mongoose";

export type SubscriptionType = {
	userId: string;
	subscriptionType: "Free" | "Basic" | "Pro";
	subscriptionStatus:
		| "Active"
		| "Expired"
		| "Cancelled"
		| "Suspended"
		| "Pending";
	subscriptionEndDate: Date;
	subscriptionAmount: number;
	subscriptionDurationMonths: number;
	autoRenew: boolean;
	lastSubscribedAt: Date;
	paymentMethod: "card" | "netbanking" | "wallet" | "upi" | "free" | null;
	paymentStatus: "Completed" | "Failed" | "Pending";
	razorpayOrderId: string | null;
	transactionHistory: {
		razorpayOrderId: string;
		razorpayPaymentId: string;
		amount: number;
		date: Date;
		paymentMethod: "card" | "netbanking" | "wallet" | "upi" | "free";
		paymentStatus: "Completed" | "Failed" | "Pending";
	}[];
	createdAt: Date;
	updatedAt: Date;
};

export interface SubscriptionDocument extends SubscriptionType, Document {
	comparePlans(targetPlan: "Free" | "Basic" | "Pro"): boolean;
}

export type SubscriptionStaticMethods = Model<SubscriptionDocument>;
