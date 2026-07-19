import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { RawEventModel } from "../../metrics/types/rawEvent.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser } from "../utils/siteAdminController.utils.js";

type RequestWithUser = Request & { userID?: string };

type Deps = {
	userModel: UserStaticMethods;
	rawEventModel: RawEventModel;
};

export async function getApiUsageStats(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { from, to } = req.query;
		const match: Record<string, unknown> = {};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

		const stats = await rawEventModel.aggregate([
			{ $match: match },
			{
				$group: {
					_id: "$apiKeyId",
					totalRequests: { $sum: 1 },
					successCount: { $sum: { $cond: [{ $eq: ["$statusClass", "2xx"] }, 1, 0] } },
					errorCount: { $sum: { $cond: [{ $in: ["$statusClass", ["4xx", "5xx"]] }, 1, 0] } },
					avgDurationMs: { $avg: "$durationMs" },
				},
			},
			{ $sort: { totalRequests: -1 } },
		]);

		return res
			.status(200)
			.json(standardResponse(true, "API usage stats fetched", stats));
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

		const { from, to } = req.query;
		const match: Record<string, unknown> = {};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

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

		return res
			.status(200)
			.json(standardResponse(true, "API latency stats fetched", stats));
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

		const { from, to } = req.query;
		const match: Record<string, unknown> = {
			statusClass: { $in: ["4xx", "5xx"] },
		};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

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

		return res
			.status(200)
			.json(standardResponse(true, "API error stats fetched", stats));
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
			return res
				.status(400)
				.json(standardResponse(false, "Missing userId", null));
		}

		const { from, to } = req.query;
		const match: Record<string, unknown> = { ownerId: userId };
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

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

		return res
			.status(200)
			.json(standardResponse(true, "API traffic by user fetched", stats));
	} catch (err) {
		next(err);
	}
}
