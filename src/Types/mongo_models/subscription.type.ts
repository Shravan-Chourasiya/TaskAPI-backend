export type SubscriptionType = {
    userId: string;
    subscriptionType: "Free" | "Basic" | "Pro";
    lastSubscribedAt: Date;
    subscriptionStatus: "Active" | "Expired" | "Cancelled" | "Suspended";
    subscriptionEndDate: Date;
    subscriptionDurationMonths: number;
    paymentMethod?: "creditCard" | "payPal" | "bankTransfer" | "upiId" | "upiApp" | "paytm";
    lastTransactionId: string | null;
    autoRenew: boolean;
    transactionHistory: {
        transactionId: string;
        paymentId: string;
        amount: number;
        date: Date;
        paymentMethod: "creditCard" | "payPal" | "bankTransfer" | "upiId" | "upiApp" | "paytm";
        status: "Completed" | "Failed" | "Pending";
    }[];
    createdAt: Date;
    updatedAt: Date;
    isSubscriptionActive: {
        isActive: boolean;
        endDate: Date;
    };
    comparePlans(targetPlan:"Free" | "Basic" | "Pro"): boolean;
}