import type { NextFunction, Request, Response } from "express";
import * as z from "zod";
import type { buySubscriptionSchema } from "../../../libs/zod/subscription.zodschema.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../../../configs/app.config.js";
import {
	createRazorpayOrder,
	verifyRazorpaySignature,
} from "../../../services/razorpay.service.js";
import {
	SUBSCRIPTION_PLANS,
	SUBSCRIPTION_CONSTANTS,
} from "../../../constants.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { Model } from "mongoose";
import {
	SubscriptionDocument,
	SubscriptionStaticMethods,
} from "../../../types/mongoModels/subscription.type.js";
import {
	UserDocument,
	UserStaticMethods,
} from "../../../types/mongoModels/user.type.js";

const freePlanBuyController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	subscriptionModel: Model<SubscriptionDocument, SubscriptionStaticMethods>,
) => {
	const { subscriptionPlanDetails }: z.infer<typeof buySubscriptionSchema> =
		req.body;
	try {
		const userId = (
			jwt.verify(
				req.cookies.acToken,
				config.ACCESS_TOKEN_JWT_SECRET,
			) as JwtPayload
		).id;

		const endDate = new Date();
		endDate.setMonth(endDate.getMonth() + 12);

		const freeOrderId = `free_${userId}_${Date.now()}`;

		const existingSubscription: SubscriptionDocument | null =
			await subscriptionModel.findOne({ userId });

		if (existingSubscription) {
			const isActive =
				existingSubscription.subscriptionStatus === "Active" &&
				new Date() < existingSubscription.subscriptionEndDate;

			if (isActive) {
				const errMsg =
					existingSubscription.subscriptionType === "Free"
						? "You already have an active Free subscription"
						: "You already have an active paid subscription. Cannot downgrade to Free while active.";
				return res.status(400).json(standardResponse(false, errMsg));
			}

			await existingSubscription.updateOne({
				$set: {
					subscriptionType: "Free",
					subscriptionStatus: "Active",
					subscriptionEndDate: endDate,
					subscriptionAmount: 0,
					subscriptionDurationMonths: subscriptionPlanDetails.duration,
					autoRenew: false,
					lastSubscribedAt: new Date(),
					paymentMethod: "free",
					paymentStatus: "Completed",
					razorpayOrderId: freeOrderId,
				},
				$push: {
					transactionHistory: {
						razorpayOrderId: freeOrderId,
						razorpayPaymentId: "",
						amount: 0,
						date: new Date(),
						paymentMethod: "free",
						paymentStatus: "Completed",
					},
				},
			});

			await userModel.findByIdAndUpdate(userId, {
				subscriptionType: "Free",
				subscriptionExpiryDate: endDate,
			});

			const updated = await subscriptionModel.findOne({ userId });
			return res
				.status(200)
				.json(
					standardResponse(
						true,
						"Free subscription activated successfully",
						updated,
					),
				);
		} else {
			const newSubscription = await subscriptionModel.create({
				userId,
				subscriptionType: "Free",
				subscriptionAmount: 0,
				subscriptionStatus: "Active",
				subscriptionEndDate: endDate,
				subscriptionDurationMonths: subscriptionPlanDetails.duration,
				autoRenew: false,
				lastSubscribedAt: new Date(),
				paymentMethod: "free",
				paymentStatus: "Completed",
				razorpayOrderId: freeOrderId,
				transactionHistory: [
					{
						razorpayOrderId: freeOrderId,
						razorpayPaymentId: "",
						amount: 0,
						date: new Date(),
						paymentMethod: "free",
						paymentStatus: "Completed",
					},
				],
			});
			await userModel.findByIdAndUpdate(userId, {
				subscriptionType: "Free",
				subscriptionExpiryDate: endDate,
			});
			return res
				.status(201)
				.json(
					standardResponse(
						true,
						"Free subscription activated successfully",
						newSubscription,
					),
				);
		}
	} catch (error) {
		next(error);
	}
};

export const buySubscriptionController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	subscriptionModel: Model<SubscriptionDocument, SubscriptionStaticMethods>,
) => {
	const { subscriptionPlanDetails }: z.infer<typeof buySubscriptionSchema> =
		req.body;
	try {
		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const userId = decoded.id;

		const userData: UserDocument | null = await userModel.findById(userId);
		if (!userData) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		if (subscriptionPlanDetails.planName === "Free") {
			return await freePlanBuyController(
				req,
				res,
				next,
				userModel,
				subscriptionModel,
			);
		}

		if (!SUBSCRIPTION_PLANS[subscriptionPlanDetails.planName]) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid subscription plan"));
		}

		if (
			SUBSCRIPTION_PLANS[subscriptionPlanDetails.planName].price !==
			subscriptionPlanDetails.price
		) {
			return res
				.status(400)
				.json(
					standardResponse(
						false,
						"Price mismatch for the selected subscription plan",
					),
				);
		}

		const existingSubscription: SubscriptionDocument | null =
			await subscriptionModel.findOne({ userId });

		const isActive =
			existingSubscription?.subscriptionStatus === "Active" &&
			new Date() < existingSubscription?.subscriptionEndDate;

		const isUpgrade = existingSubscription?.comparePlans(
			subscriptionPlanDetails.planName,
		);
		const isSamePlan =
			existingSubscription?.subscriptionType ===
			subscriptionPlanDetails.planName;

		if (isActive && !isUpgrade) {
			return res
				.status(400)
				.json(
					standardResponse(
						false,
						isSamePlan
							? "You already have an active subscription for this plan"
							: "Cannot downgrade while subscription is active",
					),
				);
		}

		// Create Razorpay order — receipt is just metadata, not used for DB lookup
		const razorpayOrder = await createRazorpayOrder(
			subscriptionPlanDetails.price,
			SUBSCRIPTION_CONSTANTS.CURRENCY,
			`receipt_${userId}_${Date.now()}`,
		);

		if (!razorpayOrder) {
			return res
				.status(500)
				.json(standardResponse(false, "Failed to create Razorpay order"));
		}

		// Store razorpayOrder.id (order_xxx) as the key for later verification lookup
		if (existingSubscription) {
			await existingSubscription.updateOne({
				$set: {
					subscriptionType: subscriptionPlanDetails.planName,
					subscriptionAmount: subscriptionPlanDetails.price,
					subscriptionStatus: "Pending",
					subscriptionDurationMonths: subscriptionPlanDetails.duration,
					autoRenew: subscriptionPlanDetails.autoRenewStatus,
					paymentStatus: "Pending",
					razorpayOrderId: razorpayOrder.id,
				},
				$push: {
					transactionHistory: {
						razorpayOrderId: razorpayOrder.id,
						razorpayPaymentId: "",
						amount: subscriptionPlanDetails.price,
						date: new Date(),
						paymentStatus: "Pending",
					},
				},
			});
		} else {
			await subscriptionModel.create({
				userId,
				subscriptionType: subscriptionPlanDetails.planName,
				subscriptionStatus: "Pending",
				subscriptionAmount: subscriptionPlanDetails.price,
				subscriptionDurationMonths: subscriptionPlanDetails.duration,
				autoRenew: subscriptionPlanDetails.autoRenewStatus,
				paymentStatus: "Pending",
				razorpayOrderId: razorpayOrder.id,
				transactionHistory: [
					{
						razorpayOrderId: razorpayOrder.id,
						razorpayPaymentId: "",
						amount: subscriptionPlanDetails.price,
						date: new Date(),
						paymentStatus: "Pending",
					},
				],
			});
		}

		return res
			.status(200)
			.json(
				standardResponse(true, "Order created successfully", { razorpayOrder }),
			);
	} catch (error) {
		next(error);
	}
};

export const verifySubscriptionPayment = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	subscriptionModel: Model<SubscriptionDocument, SubscriptionStaticMethods>,
) => {
	try {
		const { razorpayOrderId, razorpayPaymentId, razorpaySignature } = req.body;

		if (
			!razorpayOrderId ||
			!razorpayPaymentId ||
			!razorpaySignature ||
			!req.cookies.acToken
		) {
			return res
				.status(400)
				.json(
					standardResponse(
						false,
						"Missing required payment verification fields",
					),
				);
		}

		// Validate formats before using in security decision
		const ORDER_ID_RE = /^order_[A-Za-z0-9]{14,}$/;
		const PAYMENT_ID_RE = /^pay_[A-Za-z0-9]{14,}$/;
		const SIGNATURE_RE = /^[a-f0-9]{64}$/;

		if (
			!ORDER_ID_RE.test(razorpayOrderId) ||
			!PAYMENT_ID_RE.test(razorpayPaymentId) ||
			!SIGNATURE_RE.test(razorpaySignature)
		) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid payment field format"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const user: UserDocument | null = await userModel.findById(decoded.id);
		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}

		// Verify Razorpay signature
		const isValid = verifyRazorpaySignature(
			razorpayOrderId,
			razorpayPaymentId,
			razorpaySignature,
		);
		if (!isValid) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid payment signature"));
		}

		// Look up subscription directly by razorpayOrderId
		const subscription: SubscriptionDocument | null =
			await subscriptionModel.findOne({
				razorpayOrderId,
			});

		if (!subscription) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found"));
		}

		// Find the pending transaction in history
		const transaction = subscription.transactionHistory.find(
			(t: any) => t.razorpayOrderId === razorpayOrderId,
		);

		if (!transaction) {
			return res
				.status(404)
				.json(
					standardResponse(
						false,
						"Transaction not found in subscription history",
					),
				);
		}

		const endDate = new Date(
			Date.now() +
				subscription.subscriptionDurationMonths *
					SUBSCRIPTION_CONSTANTS.DAYS_PER_MONTH *
					24 *
					60 *
					60 *
					1000,
		);

		subscription.subscriptionStatus = "Active";
		subscription.lastSubscribedAt = new Date();
		subscription.subscriptionEndDate = endDate;
		subscription.paymentStatus = "Completed";
		subscription.paymentMethod = "upi";

		transaction.razorpayPaymentId = razorpayPaymentId;
		transaction.date = new Date();
		transaction.paymentStatus = "Completed";
		transaction.paymentMethod = "upi";

		user.subscriptionType = subscription.subscriptionType;
		user.subscriptionExpiryDate = endDate;

		await user.save();
		await subscription.save();

		return res.json(standardResponse(true, "Payment verified successfully"));
	} catch (error) {
		next(error);
	}
};

export const razorpayWebhookHandler = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const secret = req.body.secret;
		if (!secret) {
			return res
				.status(401)
				.json(standardResponse(false, "Unauthorized: Missing webhook secret"));
		}
		return res.status(200).json(standardResponse(true, "Webhook received"));
	} catch (error) {
		next(error);
	}
};
