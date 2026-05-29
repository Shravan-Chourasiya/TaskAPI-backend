import type { NextFunction, Request, Response } from "express";
import * as z from "zod";
import type { buySubscriptionSchema } from "../../../libs/zod/subscription.zodschema.js";
import { SubscriptionModel } from "../models/subscription/subscription.model.js";
import userModel from "../models/user.schema.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../../../configs/app.config.js";
import crypto from "crypto";
import {
	createRazorpayOrder,
	verifyRazorpaySignature,
} from "../../../services/razorpay.service.js";
import { SUBSCRIPTION_PLANS } from "../../../constants.js";

const freePlanBuyController = async (
	req: Request,
	res: Response,
	next: NextFunction,
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

		const userSubData = await SubscriptionModel.findById(userId);
		
		if (userSubData) {
			// Check if user already has an active subscription
			const isActiveSubscription =
				userSubData.subscriptionStatus === "Active" &&
				new Date() < userSubData.subscriptionEndDate;

			if (isActiveSubscription) {
				return res.status(400).json({
					message:
						userSubData.subscriptionType === "Free"
							? "You already have an active Free subscription"
							: "You already have an active paid subscription. Cannot downgrade to Free while active.",
				});
			}

			// Update existing subscription record instead of creating new one
			const transactionId = "txn_" + crypto.randomBytes(9).toString("hex");
			const endDate = new Date();
			endDate.setMonth(endDate.getMonth() + 12);
			console.warn(
				"###3::::: Updating subscription for Free plan with transactionId:",
				transactionId,
			);
			await userSubData.updateOne({
				$set: {
					subscriptionType: subscriptionPlanDetails.planName,
					subscriptionStatus: "Active",
					subscriptionEndDate: endDate,
					subscriptionAmount: 0,
					subscriptionDurationMonths: subscriptionPlanDetails.duration,
					autoRenew: false,
					lastSubscribedAt: new Date(),
					lastTransactionId: transactionId,
					paymentMethod: "free",
					paymentStatus: "Completed",
					transactionId,
				},
				$push: {
					transactionHistory: {
						transactionId,
						paymentId: `free_plan_1_year_${userId}`,
						amount: 0,
						date: new Date(),
						paymentMethod: "free",
						paymentStatus: "Completed",
					},
				},
			});
			console.warn(
				"###4::::: Subscription updated for Free plan with transactionId:",
				transactionId,
			);
			const updatedSubscription = await SubscriptionModel.findOne({ userId });

			return res.status(200).json({
				message: "Free subscription activated successfully",
				subscription: updatedSubscription,
			});
		} else {
			// Create new subscription record if none exists
			const transactionId = "txn_" + crypto.randomBytes(9).toString("hex");
			const subscriptionData = {
				userId,
				subscriptionType: subscriptionPlanDetails.planName,
				subscriptionAmount: 0,
				subscriptionStatus: "Active",
				subscriptionDurationMonths: subscriptionPlanDetails.duration,
				autoRenew: false,
				lastSubscribedAt: new Date(),
				paymentMethod: null,
				paymentStatus: "Completed",
				transactionId,
			};
			const newSubscription = new SubscriptionModel(subscriptionData);
			await newSubscription.save();
			if (!newSubscription) {
				return res
					.status(500)
					.json({ success: false, message: "Failed to create subscription" });
			}
			return res.status(201).json({
				success: true,
				message: "Free subscription activated successfully",
				subscription: newSubscription,
			});
		}
	} catch (error) {
		next(error);
	}
};

export const buySubscriptionController = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	// const Session = await SubscriptionModel.db.startSession();
	// console.warn(req.body);
	const { subscriptionPlanDetails }: z.infer<typeof buySubscriptionSchema> =
		req.body;
	try {
		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const userId = decoded.id;

		const userData = await userModel.findById(userId);
		if (!userData) {
			return res.status(404).json({ message: "User not found" });
		}
		const isPlanFree = subscriptionPlanDetails.planName === "Free";

		if (isPlanFree) {
			return await freePlanBuyController(req, res, next);
		}
		const existingSubscription = await SubscriptionModel.findOne(
			{ userId },
			// { session: Session },
		);

		const planNameFromDb = existingSubscription?.subscriptionType;

		// Check if user is trying to buy the same plan they already have
		if (
			planNameFromDb === subscriptionPlanDetails.planName &&
			existingSubscription?.subscriptionStatus === "Active"
		) {
			return res.status(400).json({
				success: false,
				message: "You already have this subscription plan",
			});
		}

		if (!SUBSCRIPTION_PLANS[subscriptionPlanDetails.planName]) {
			return res.status(400).json({
				success: false,
				message: "Invalid subscription plan",
			});
		}

		if (
			SUBSCRIPTION_PLANS[subscriptionPlanDetails.planName].price !==
			subscriptionPlanDetails.price
		) {
			return res.status(400).json({
				success: false,
				message: "Price mismatch for the selected subscription plan",
			});
		}

		const isActive =
			existingSubscription?.subscriptionStatus === "Active" &&
			new Date() < existingSubscription?.subscriptionEndDate
				? true
				: false;
		const isUpgrade = existingSubscription?.comparePlans(
			subscriptionPlanDetails.planName,
		);
		const isSamePlan =
			existingSubscription?.subscriptionType ===
			subscriptionPlanDetails.planName;

		// Block if active and not upgrading
		if (isActive && !isUpgrade) {
			return res.status(400).json({
				success: false,
				message: isSamePlan
					? "You already have an active subscription for this plan"
					: "Cannot downgrade while subscription is active",
			});
		}

		const transactionId = "txn_" + crypto.randomBytes(9).toString("hex");
		const razorpayOrder = await createRazorpayOrder(
			subscriptionPlanDetails.price,
			"INR",
			`receipt_${transactionId}`,
		);
		console.warn(razorpayOrder);
		if (!razorpayOrder) {
			return res
				.status(500)
				.json({ message: "Failed to create Razorpay order" });
		}
		if (existingSubscription && razorpayOrder) {
			const updatedSubscriptionData = await existingSubscription.updateOne({
				$set: {
					subscriptionType: subscriptionPlanDetails.planName,
					subscriptionAmount: subscriptionPlanDetails.price,
					subscriptionStatus: "Pending",
					subscriptionDurationMonths: subscriptionPlanDetails.duration,
					autoRenew: subscriptionPlanDetails.autoRenewStatus,
					paymentStatus: "Pending",
					transactionId,
				},
				$push: {
					transactionHistory: {
						transactionId,
						amount: subscriptionPlanDetails.price,
						date: new Date(),
						paymentStatus: "Pending",
						razorPayID: razorpayOrder.id,
					},
				},
			});
			if (!updatedSubscriptionData) {
				return res
					.status(500)
					.json({ success: false, message: "Failed to create subscription" });
			}
			return res.status(200).json({
				success: true,
				message: "Subscription updated successfully",
				data: updatedSubscriptionData,
				razorpayOrder,
			});
		} else {
			const newSubscription = await SubscriptionModel.create({
				userId,
				subscriptionType: subscriptionPlanDetails.planName,
				subscriptionStatus: "Pending",
				subscriptionAmount: subscriptionPlanDetails.price,
				subscriptionDurationMonths: subscriptionPlanDetails.duration,
				autoRenew: subscriptionPlanDetails.autoRenewStatus,
				paymentStatus: "Pending",
				transactionId,
				transactionHistory: [
					{
						transactionId,
						razorPayID: razorpayOrder.id,
						date: new Date(),
						amount: subscriptionPlanDetails.price,
						paymentStatus: "Pending",
					},
				],
			});

			if (!newSubscription) {
				// await Session.abortTransaction();
				return res
					.status(500)
					.json({ success: false, message: "Failed to create subscription" });
			}
			// await Session.commitTransaction();
			return res.status(201).json({
				success: true,
				message: "Subscription purchased successfully",
				subscription: newSubscription,
				razorpayOrder,
			});
		}
	} catch (error) {
		// 	await Session.abortTransaction();
		next(error);
	}
	// } finally {
	// 	await Session.endSession()
	// }
};

// export const cancelSubscription = async (req:Request, res:Response,next:NextFunction) => {}
// export const autoRenewSubscription = async (req:Request, res:Response,next:NextFunction) => {}
// export const getSubscriptionDetails = async (req:Request, res:Response,next:NextFunction) => {}
// export const getSubscriptionHistory = async (req:Request, res:Response,next:NextFunction) => {}

// export const getSubscriptionStatus = null

// 2. Verify Payment Endpoint
export const verifySubscriptionPayment = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const { transactionId, razorPayID, signature, razorPayData } = req.body;
		console.warn("###1:::::", razorPayData);
		if (!transactionId || !razorPayID || !signature || !razorPayData) {
			return res
				.status(400)
				.json({ message: "Missing required payment verification fields" });
		}
		const transactionIdTrimmed =
			razorPayData.transactionId.split("receipt_")[1]; // Extract the original transactionId without any suffix

		console.warn(
			"###2::::: Extracted transactionId for verification:",
			transactionIdTrimmed,
		);
		// Verify signature
		const isValid = verifyRazorpaySignature(
			transactionId,
			razorPayID,
			signature,
		);
		if (!isValid) {
			return res.status(400).json({ message: "Invalid payment signature" });
		}

		// Update subscription to Active
		const subscription = await SubscriptionModel.findOne({
			transactionId: transactionIdTrimmed,
		});
		console.warn(
			"###3::::: Subscription found for transactionId:",
			subscription,
		);
		if (!subscription) {
			return res.status(404).json({ message: "Subscription not found" });
		}

		// Find the specific transaction instead of assuming index 0
		const transaction = subscription.transactionHistory.find(
			(t) => t.transactionId === transactionIdTrimmed,
		);
		console.warn(
			"###4::::: Transaction found in subscription history:",
			transaction,
		);
		if (!transaction) {
			return res
				.status(404)
				.json({ message: "Transaction not found in subscription history" });
		}

		const endDate = new Date(
			new Date().getTime() +
				subscription.subscriptionDurationMonths * 28 * 24 * 60 * 60 * 1000,
		);

		subscription.subscriptionStatus = "Active";
		subscription.lastSubscribedAt = new Date();
		subscription.subscriptionEndDate = endDate;
		subscription.paymentStatus = "Completed";
		subscription.paymentMethod = "upi";
		console.warn("###5::::: Updating subscription with payment details");
		transaction.razorPayID = razorPayID;
		transaction.date = new Date();
		transaction.paymentStatus = "Completed";
		transaction.paymentMethod = "upi";
		console.warn("###6::::: Saving updated subscription");
		await subscription.save();
		console.warn("###7::::: Subscription updated and saved successfully");
		return res.json({
			success: true,
			message: "Payment verified successfully",
		});
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
			return res.status(401).json({ message: "Unauthorized" });
		}
		return res.status(200).json({ message: "Webhook received" });
	} catch (error) {
		next(error);
	}
};
