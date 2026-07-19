import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { RawEventModel } from "../../metrics/types/rawEvent.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser, isAdmin } from "../utils/siteAdminController.utils.js";

type RequestWithUser = Request & { userID?: string };

type Deps = {
	userModel: UserStaticMethods;
	rawEventModel: RawEventModel;
};

export async function getUserGrowthMetrics(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const stats = await userModel.getStatistics();
		const growth = await (userModel as any).aggregate([
			{
				$group: {
					_id: {
						year: { $year: "$createdAt" },
						month: { $month: "$createdAt" },
					},
					newUsers: { $sum: 1 },
				},
			},
			{ $sort: { "_id.year": -1, "_id.month": -1 } },
			{ $limit: 12 },
		]);

		return res
			.status(200)
			.json(standardResponse(true, "User growth metrics fetched", { stats, growth }));
	} catch (err) {
		next(err);
	}
}

export async function getEngagementMetrics(
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

		const engagement = await rawEventModel.aggregate([
			{ $match: match },
			{
				$group: {
					_id: {
						ownerId: "$ownerId",
						day: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
					},
					requestCount: { $sum: 1 },
				},
			},
			{
				$group: {
					_id: "$_id.day",
					activeUsers: { $sum: 1 },
					totalRequests: { $sum: "$requestCount" },
				},
			},
			{ $sort: { _id: -1 } },
			{ $limit: 30 },
		]);

		return res
			.status(200)
			.json(standardResponse(true, "Engagement metrics fetched", engagement));
	} catch (err) {
		next(err);
	}
}

export async function getFeatureUsageStats(
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

		const usage = await rawEventModel.aggregate([
			{ $match: match },
			{
				$group: {
					_id: { route: "$route", method: "$method" },
					callCount: { $sum: 1 },
					avgDurationMs: { $avg: "$durationMs" },
				},
			},
			{ $sort: { callCount: -1 } },
		]);

		return res
			.status(200)
			.json(standardResponse(true, "Feature usage stats fetched", usage));
	} catch (err) {
		next(err);
	}
}

export async function getSubscriptionTrends(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const trends = await (userModel as any).aggregate([
			{
				$group: {
					_id: {
						subscriptionType: "$subscriptionType",
						year: { $year: "$createdAt" },
						month: { $month: "$createdAt" },
					},
					count: { $sum: 1 },
				},
			},
			{ $sort: { "_id.year": -1, "_id.month": -1 } },
			{ $limit: 36 },
		]);

		return res
			.status(200)
			.json(standardResponse(true, "Subscription trends fetched", trends));
	} catch (err) {
		next(err);
	}
}

export async function exportMetrics(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can export metrics", null));
		}

		const { format = "json", from, to } = req.query;
		if (!["json", "csv"].includes(format as string)) {
			return res
				.status(400)
				.json(standardResponse(false, "Supported formats: json, csv", null));
		}

		const match: Record<string, unknown> = {};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

		const events = await rawEventModel.find(match).sort({ timestamp: -1 }).limit(10000).lean();

		if (format === "csv") {
			const headers = "timestamp,apiKeyId,ownerId,route,method,httpStatusCode,statusClass,durationMs,error\n";
			const rows = events
				.map((e) =>
					[e.timestamp.toISOString(), e.apiKeyId, e.ownerId, e.route, e.method, e.httpStatusCode, e.statusClass, e.durationMs, e.error ?? ""].join(","),
				)
				.join("\n");
			res.setHeader("Content-Type", "text/csv");
			res.setHeader("Content-Disposition", "attachment; filename=metrics.csv");
			return res.status(200).send(headers + rows);
		}

		return res
			.status(200)
			.json(standardResponse(true, "Metrics exported", events));
	} catch (err) {
		next(err);
	}
}

export async function generateReport(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can generate reports", null));
		}

		const { type, from, to } = req.query;
		if (!type || !["usage", "errors", "latency", "growth"].includes(type as string)) {
			return res
				.status(400)
				.json(standardResponse(false, "type must be one of: usage, errors, latency, growth", null));
		}

		const match: Record<string, unknown> = {};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

		let report: unknown;

		if (type === "usage") {
			report = await rawEventModel.aggregate([
				{ $match: match },
				{ $group: { _id: "$apiKeyId", totalRequests: { $sum: 1 } } },
				{ $sort: { totalRequests: -1 } },
			]);
		} else if (type === "errors") {
			report = await rawEventModel.aggregate([
				{ $match: { ...match, statusClass: { $in: ["4xx", "5xx"] } } },
				{ $group: { _id: { route: "$route", error: "$error" }, count: { $sum: 1 } } },
				{ $sort: { count: -1 } },
			]);
		} else if (type === "latency") {
			report = await rawEventModel.aggregate([
				{ $match: match },
				{ $group: { _id: "$route", avgMs: { $avg: "$durationMs" }, maxMs: { $max: "$durationMs" } } },
				{ $sort: { avgMs: -1 } },
			]);
		} else {
			report = await userModel.getStatistics();
		}

		return res
			.status(200)
			.json(standardResponse(true, `${type} report generated`, report as object));
	} catch (err) {
		next(err);
	}
}
