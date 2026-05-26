export type SubscriptionType = {
    userId: string;
    subscriptionType: "Free" | "Basic" | "Pro";
    subscriptionStatus: "Active" | "Expired" | "Cancelled" | "Suspended";
    subscriptionEndDate: Date;
    subscriptionAmount: number;
    subscriptionDurationMonths: number;
    autoRenew: boolean;
    lastSubscribedAt: Date;
    lastTransactionId: string | null;
    paymentMethod: "card" | "netbanking" | "wallet" | "upi" | null;
    paymentStatus: "Completed" | "Failed" | "Pending";
    transactionId: string;
    transactionHistory: {
        transactionId: string;
        paymentId: string;
        amount: number;
        date: Date;
        paymentMethod: "card" | "netbanking" | "wallet" | "upi";
        paymentStatus: "Completed" | "Failed" | "Pending";
    }[];
    createdAt: Date;
    updatedAt: Date;
    comparePlans(targetPlan:"Free" | "Basic" | "Pro"): boolean;
}