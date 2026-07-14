import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { SubscriptionStaticMethods } from "../../../types/mongoModels/subscription.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser, isAdmin } from "../utils/siteAdminController.utils.js";
import z from "zod";
import { modifySubscriptionSchema } from "../../../libs/zod/siteAdmin.zodschema.js";

type RequestWithUser = Request & { userID?: string };

type Deps = {
	userModel: UserStaticMethods;
	subscriptionModel: SubscriptionStaticMethods;
};

export async function getUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { userId } = req.params;
		if (!userId) {
			return res.status(400).json(standardResponse(false, "Missing userId", null));
		}
		const subscription = await subscriptionModel.findOne({ userId }).lean();
		if (!subscription) {
			return res.status(404).json(standardResponse(false, "Subscription not found", null));
		}

		return res.status(200).json(standardResponse(true, "Subscription fetched successfully", subscription));
	} catch (err) {
		next(err);
	}
}

export async function modifyUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		if (!isAdmin(admin)) {
			return res.status(403).json(standardResponse(false, "Only admins can modify subscriptions", null));
		}

		const { userId } = req.params;
		if (!userId) {
			return res.status(400).json(standardResponse(false, "Missing userId", null));
		}
		const { subscriptionType, subscriptionStatus, subscriptionEndDate }: z.infer<typeof modifySubscriptionSchema> = req.body;

		const updated = await subscriptionModel.findOneAndUpdate(
			{ userId },
			{ $set: { subscriptionType, subscriptionStatus, subscriptionEndDate } },
			{ new: true },
		);
		if (!updated) {
			return res.status(404).json(standardResponse(false, "Subscription not found", null));
		}

		// keep UserType.subscriptionType in sync
		await userModel.findByIdAndUpdate(userId, {
			$set: {
				subscriptionType,
				subscriptionExpiryDate: subscriptionEndDate,
			},
		});

		return res.status(200).json(standardResponse(true, "Subscription updated successfully", updated));
	} catch (err) {
		next(err);
	}
}
