import type { Request, NextFunction, Response } from "express";
import { Model } from "mongoose";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { RawEventModel } from "../../metrics/types/rawEvent.type.js";
import type { IRollupBucket } from "../../metrics/types/rollupData.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser, applyHardWindowCap } from "../utils/siteAdminController.utils.js";
import {
	selectRollupTier,
	aggregateBucketsSiteWide,
} from "../../../utils/rollupAggregations.js";

type RequestWithUser = Request & { userID?: string };

type Deps = {
	userModel: UserStaticMethods;
	rawEventModel: RawEventModel;
	Rollup5m: Model<IRollupBucket>;
	Rollup1h: Model<IRollupBucket>;
	Rollup1d: Model<IRollupBucket>;
};

// Per-dimension (route/error) analytics stay on raw_events, hard-capped to 7
// days so a wide window can't turn into a full raw scan. Default: last 24h.
function rawWindow(req: Request): { from: Date; to: Date } {
	const { from, to } = req.query;
	const end = to ? new Date(to as string) : new Date();
	const start = from ? new Date(from as string) : new Date(end.getTime() - 24 * 60 * 60 * 1000);
	applyHardWindowCap(start, end);
	return { from: start, to: end };
}

export async function getApiUsageStats(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, Rollup5m, Rollup1h, Rollup1d }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { from: rawFrom, to: rawTo } = req.query;
		const end = rawTo ? new Date(rawTo as string) : new Date();
		const start = rawFrom ? new Date(rawFrom as string) : new Date(end.getTime() - 24 * 60 * 60 * 1000);
		applyHardWindowCap(start, end);

		const { tier, model } = selectRollupTier(start, end, { Rollup5m, Rollup1h, Rollup1d });
		const stats = await aggregateBucketsSiteWide(model, start, end);

		return res.status(200).json(
			standardResponse(true, "API usage stats fetched", { tier, buckets: stats }),
		);
	} catch (err) {
		next(err);
	}
}

export async function getApiLatencyStats(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { from, to } = rawWindow(req);
		const match: Record<string, unknown> = {
			timestamp: { $gte: from, $lte: to },
		};

		const stats = await rawEventModel.aggregate([
			{ $match: match },
			{
				$group: {
					_id: "$route",
					avgDurationMs: { $avg: "$durationMs" },
					minDurationMs: { $min: "$durationMs" },
					maxDurationMs: { $max: "$durationMs" },
					requestCount: { $sum: 1 },
				},
			},
			{ $sort: { avgDurationMs: -1 } },
		]);

		return res.status(200).json(standardResponse(true, "API latency stats fetched", stats));
	} catch (err) {
		next(err);
	}
}

export async function getApiErrorStats(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { from, to } = rawWindow(req);
		const match: Record<string, unknown> = {
			statusClass: { $in: ["4xx", "5xx"] },
			timestamp: { $gte: from, $lte: to },
		};

		const stats = await rawEventModel.aggregate([
			{ $match: match },
			{
				$group: {
					_id: { route: "$route", statusClass: "$statusClass", error: "$error" },
					count: { $sum: 1 },
				},
			},
			{ $sort: { count: -1 } },
		]);

		return res.status(200).json(standardResponse(true, "API error stats fetched", stats));
	} catch (err) {
		next(err);
	}
}

export async function getApiTrafficByUser(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { userId } = req.params;
		if (!userId) {
			return res.status(400).json(standardResponse(false, "Missing userId", null));
		}

		const { from, to } = rawWindow(req);
		const match: Record<string, unknown> = {
			ownerId: userId,
			timestamp: { $gte: from, $lte: to },
		};

		const stats = await rawEventModel.aggregate([
			{ $match: match },
			{
				$group: {
					_id: { apiKeyId: "$apiKeyId", route: "$route" },
					totalRequests: { $sum: 1 },
					avgDurationMs: { $avg: "$durationMs" },
					errorCount: { $sum: { $cond: [{ $in: ["$statusClass", ["4xx", "5xx"]] }, 1, 0] } },
				},
			},
			{ $sort: { totalRequests: -1 } },
		]);

		return res.status(200).json(standardResponse(true, "API traffic by user fetched", stats));
	} catch (err) {
		next(err);
	}
}
