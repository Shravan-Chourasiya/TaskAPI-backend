import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { SubscriptionStaticMethods } from "../../../types/mongoModels/subscription.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import {
	resolveAdminUser,
	isAdmin,
} from "../utils/siteAdminController.utils.js";
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
			return res
				.status(400)
				.json(standardResponse(false, "Missing userId", null));
		}
		const subscription = await subscriptionModel.findById({ userId: String(userId) }).lean();
		if (!subscription) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		return res
			.status(200)
			.json(
				standardResponse(
					true,
					"Subscription fetched successfully",
					subscription,
				),
			);
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
			return res
				.status(403)
				.json(
					standardResponse(false, "Only admins can modify subscriptions", null),
				);
		}

		const { userId } = req.params;
		if (!userId) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing userId", null));
		}
		const {
			subscriptionType,
			subscriptionStatus,
			subscriptionEndDate,
		}: z.infer<typeof modifySubscriptionSchema> = req.body;

		const updated = await subscriptionModel.findOneAndUpdate(
			{ userId },
			{ $set: { subscriptionType, subscriptionStatus, subscriptionEndDate } },
			{ new: true },
		);
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		// keep UserType.subscriptionType in sync
		await userModel.findByIdAndUpdate(userId, {
			$set: {
				subscriptionType,
				subscriptionExpiryDate: subscriptionEndDate,
			},
		});

		return res
			.status(200)
			.json(
				standardResponse(true, "Subscription updated successfully", updated),
			);
	} catch (err) {
		next(err);
	}
}

// ================================================ NEWLY ADDED =============================================

export async function createUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(false, "Only admins can create subscriptions", null),
				);
		}

		const { userId } = req.params;
		const { subscriptionType, subscriptionStatus, subscriptionEndDate } =
			req.body;

		if (!subscriptionType || !subscriptionStatus || !subscriptionEndDate) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required fields", null));
		}

		const existing = await subscriptionModel.findById({ userId });
		if (existing) {
			return res
				.status(409)
				.json(
					standardResponse(
						false,
						"Subscription already exists for this user",
						null,
					),
				);
		}

		const subscription = await subscriptionModel.create({
			userId:String(userId),
			subscriptionType,
			subscriptionStatus,
			subscriptionEndDate: new Date(subscriptionEndDate),
			paymentMethod: subscriptionType === "Free" ? "free" : null,
			paymentStatus: subscriptionType === "Free" ? "Completed" : "Pending",
		});

		await userModel.findByIdAndUpdate(userId, {
			$set: {
				subscriptionType,
				subscriptionExpiryDate: new Date(subscriptionEndDate),
			},
		});

		return res
			.status(201)
			.json(
				standardResponse(
					true,
					"Subscription created successfully",
					subscription,
				),
			);
	} catch (err) {
		next(err);
	}
}

export async function deleteUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(false, "Only admins can delete subscriptions", null),
				);
		}

		const { userId } = req.params;
		const deleted = await subscriptionModel.findOneAndDelete({ userId:String(userId) });
		if (!deleted) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		await userModel.findByIdAndUpdate(userId, {
			$set: { subscriptionType: "Free" },
			$unset: { subscriptionExpiryDate: "" },
		});

		return res
			.status(200)
			.json(standardResponse(true, "Subscription deleted successfully", null));
	} catch (err) {
		next(err);
	}
}

export async function blacklistUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(
						false,
						"Only admins can blacklist subscriptions",
						null,
					),
				);
		}

		const { userId } = req.params;
		const updated = await subscriptionModel.findOneAndUpdate(
			{ userId:String(userId) },
			{ $set: { subscriptionStatus: "Cancelled" } },
			{ new: true },
		);
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		return res
			.status(200)
			.json(
				standardResponse(true, "Subscription blacklisted successfully", null),
			);
	} catch (err) {
		next(err);
	}
}

export async function suspendUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { userId } = req.params;
		const updated = await subscriptionModel.findOneAndUpdate(
			{ userId: String(userId) },
			{ $set: { subscriptionStatus: "Suspended" } },
			{ new: true },
		);
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		return res
			.status(200)
			.json(
				standardResponse(true, "Subscription suspended successfully", null),
			);
	} catch (err) {
		next(err);
	}
}

// restores a suspended or cancelled subscription (not expired)
export async function restoreUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(
						false,
						"Only admins can restore subscriptions",
						null,
					),
				);
		}

		const { userId } = req.params;
		const sub = await subscriptionModel.findById({ userId });
		if (!sub) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		if (sub.subscriptionStatus === "Expired") {
			return res
				.status(400)
				.json(
					standardResponse(
						false,
						"Cannot restore an expired subscription",
						null,
					),
				);
		}

		sub.subscriptionStatus = "Active";
		await sub.save();

		return res
			.status(200)
			.json(standardResponse(true, "Subscription restored successfully", null));
	} catch (err) {
		next(err);
	}
}

export async function extendUserTrial(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can extend trials", null));
		}

		const { userId } = req.params;
		const { days }: { days: number } = req.body;

		if (!days || typeof days !== "number" || days <= 0) {
			return res
				.status(400)
				.json(standardResponse(false, "Valid days value is required", null));
		}

		const sub = await subscriptionModel.findById({ userId: String(userId) });
		if (!sub) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		const base =
			sub.subscriptionEndDate > new Date()
				? sub.subscriptionEndDate
				: new Date();
		const newEndDate = new Date(base.getTime() + days * 24 * 60 * 60 * 1000);
		sub.subscriptionEndDate = newEndDate;
		await sub.save();

		await userModel.findByIdAndUpdate(userId, {
			$set: { subscriptionExpiryDate: newEndDate },
		});

		return res
			.status(200)
			.json(
				standardResponse(true, "Trial extended successfully", { newEndDate }),
			);
	} catch (err) {
		next(err);
	}
}

export async function expireUserSubscription(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(false, "Only admins can expire subscriptions", null),
				);
		}

		const { userId } = req.params;
		const updated = await subscriptionModel.findOneAndUpdate(
			{ userId: String(userId) },
			{
				$set: {
					subscriptionStatus: "Expired",
					subscriptionEndDate: new Date(),
				},
			},
			{ new: true },
		);
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		await userModel.findByIdAndUpdate(userId, {
			$set: { subscriptionExpiryDate: new Date() },
		});

		return res
			.status(200)
			.json(standardResponse(true, "Subscription expired successfully", null));
	} catch (err) {
		next(err);
	}
}

export async function changeUserSubscriptionTier(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, subscriptionModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(
						false,
						"Only admins can change subscription tiers",
						null,
					),
				);
		}

		const { userId } = req.params;
		const { subscriptionType }: { subscriptionType: "Free" | "Basic" | "Pro" } =
			req.body;

		if (
			!subscriptionType ||
			!["Free", "Basic", "Pro"].includes(subscriptionType)
		) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid subscription tier", null));
		}

		const updated = await subscriptionModel.findOneAndUpdate(
			{ userId: String(userId) },
			{ $set: { subscriptionType } },
			{ new: true },
		);
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "Subscription not found", null));
		}

		await userModel.findByIdAndUpdate(userId, { $set: { subscriptionType } });

		return res
			.status(200)
			.json(
				standardResponse(
					true,
					"Subscription tier changed successfully",
					updated,
				),
			);
	} catch (err) {
		next(err);
	}
}
