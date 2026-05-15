import type { NextFunction, Request, Response } from "express";
import * as z from "zod";
import type { buySubscriptionSchema } from "../../../libs/zod/subscription.zodschema.js";
import { SubscriptionModel } from "../models/subscription/subscription.model.js";
import userModel from "../models/user.schema.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../../../configs/app.config.js";
import crypto from "crypto";

const freePlanBuyController = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	const Session = await SubscriptionModel.db.startSession();
	const {
		userId,
		subscriptionPlanDetails,
	}: z.infer<typeof buySubscriptionSchema> = req.body;
	try {
		Session.startTransaction();
		const userSubData = await SubscriptionModel.findOne(
			{ userId },
			{ session: Session },
		);
		if (userSubData?.subscriptionType !== "Free") {
			return res.status(400).json({
				message:
					"You already have an active subscription for this plan or a higher plan",
			});
		}

		const transactionId = "txn_" + crypto.randomBytes(9).toString("hex");
		const newSubscription = await SubscriptionModel.create(
			[
				{
					userId,
					subscriptionType: subscriptionPlanDetails.planName,
					subscriptionDurationMonths: subscriptionPlanDetails.duration,
					paymentMethod: "Free Plan",
					autoRenew: subscriptionPlanDetails.autoRenewStatus,
					lastTransactionId: transactionId,
					lastSubscribedAt: new Date(),
					subscriptionEndDate: new Date(
						new Date().setMonth(new Date().getMonth() + 12),
					),
					transactionHistory: [
						{
							transactionId,
							paymentId: `free_plan_1_year_${userId}`,
							amount: 0,
							date: new Date(),
							paymentMethod: "Free Plan",
							status: "Completed",
						},
					],
				},
			],
			{ session: Session },
		);

		if (!newSubscription) {
			await Session.abortTransaction();
			return res.status(500).json({ message: "Failed to create subscription" });
		}
		await Session.commitTransaction();
		return res.status(201).json({
			message: "Subscription purchased successfully",
			subscription: newSubscription,
		});
	} catch (error) {
		await Session.abortTransaction();
		next(error);
	} finally {
		await Session.endSession();
	}
};

export const buySubscriptionController = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	const Session = await SubscriptionModel.db.startSession();
	const {
		subscriptionPlanDetails,
	}: z.infer<typeof buySubscriptionSchema> = req.body;
	try {
		Session.startTransaction();
		
		const decoded= jwt.verify(req.cookies.token, config.ACCESS_TOKEN_JWT_SECRET) as JwtPayload;
		const userId = decoded.userId;

		const isPlanFree = subscriptionPlanDetails.planName === "Free";
		if (isPlanFree) {
			return await freePlanBuyController(req, res, next);
		}
		const userData = await userModel.findOne(
			{ _id: userId },
			{ session: Session },
		);
		if (isPlanFree) {
			console.error("free");
		}
		if (!userData) {
			return res.status(404).json({ message: "User not found" });
		}

		const existingSubscription = await SubscriptionModel.findOne(
			{ userId },
			{ session: Session },
		);
		if (existingSubscription) {
			const isActive = existingSubscription.isSubscriptionActive.isActive;
			const isUpgrade = existingSubscription.comparePlans(
				subscriptionPlanDetails.planName,
			);
			const isSamePlan =
				existingSubscription.subscriptionType ===
				subscriptionPlanDetails.planName;

			// Block if active and not upgrading
			if (isActive && !isUpgrade) {
				return res.status(400).json({
					message: isSamePlan
						? "You already have an active subscription for this plan"
						: "Cannot downgrade while subscription is active",
				});
			}

			// Block buying Free plan explicitly
			if (subscriptionPlanDetails.planName === "Free") {
				return res.status(400).json({ message: "Cannot purchase Free plan" });
			}
		}
		const transactionId = "txn_" + crypto.randomBytes(9).toString("hex");

		//TODO: initiate payment process and get payment confirmation
		const newSubscription = await SubscriptionModel.create(
			[
				{
					userId,
					subscriptionType: subscriptionPlanDetails.planName,
					subscriptionDurationMonths: subscriptionPlanDetails.duration,
					paymentMethod: "creditCard", //TODO: This should come from the payment process
					autoRenew: subscriptionPlanDetails.autoRenewStatus,
					lastTransactionId: transactionId,
					lastSubscribedAt: new Date(),
					transactionHistory: [
						{
							transactionId,
							paymentId: "chaibiscuit", //TODO: This should come from the payment process
							amount: subscriptionPlanDetails.price,
							date: new Date(),
							paymentMethod: "creditCard", //TODO: This should come from the payment process
							status: "Completed", //TODO: This should come from the payment process
						},
					],
				},
			],
			{ session: Session },
		);

		if (!newSubscription) {
			await Session.abortTransaction();
			return res.status(500).json({ message: "Failed to create subscription" });
		}
		await Session.commitTransaction();
		return res.status(201).json({
			message: "Subscription purchased successfully",
			subscription: newSubscription,
		});
	} catch (error) {
		await Session.abortTransaction();
		next(error);
	} finally {
		await Session.endSession();
	}
};

// export const cancelSubscription = async (req:Request, res:Response,next:NextFunction) => {}
// export const autoRenewSubscription = async (req:Request, res:Response,next:NextFunction) => {}
// export const getSubscriptionDetails = async (req:Request, res:Response,next:NextFunction) => {}
// export const getSubscriptionHistory = async (req:Request, res:Response,next:NextFunction) => {}

// export const getSubscriptionStatus = null
