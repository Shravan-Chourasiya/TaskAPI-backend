import type { Request, NextFunction, Response } from "express";
import { Model } from "mongoose";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { RawEventModel } from "../../metrics/types/rawEvent.type.js";
import type { IRollupBucket } from "../../metrics/types/rollupData.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser, isAdmin, applyHardWindowCap } from "../utils/siteAdminController.utils.js";
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

// Per-dimension (route/method) analytics stay on raw_events, hard-capped to 7
// days. Default: last 24h.
function rawWindow(req: Request): { from: Date; to: Date } {
	const { from, to } = req.query;
	const end = to ? new Date(to as string) : new Date();
	const start = from ? new Date(from as string) : new Date(end.getTime() - 24 * 60 * 60 * 1000);
	applyHardWindowCap(start, end);
	return { from: start, to: end };
}

// Unify the optional from/to query into a closed window (rollup-backed routes
// may span longer ranges — the tier selection handles granularity).
function windowOr24h(req: Request): { from: Date; to: Date } {
	const { from, to } = req.query;
	const end = to ? new Date(to as string) : new Date();
	const start = from ? new Date(from as string) : new Date(end.getTime() - 24 * 60 * 60 * 1000);
	return { from: start, to: end };
}

export async function getUserGrowthMetrics(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel }: Deps,
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
	{ userModel, Rollup1d }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { from, to } = windowOr24h(req);

		// Day-precision engagement — run on the 1d tier directly. Running on a
		// finer tier (1h) would double-count owners across intra-day buckets.
		const engagement = await Rollup1d.aggregate([
			{ $match: { bucketStart: { $gte: from, $lt: to } } },
			{
				$group: {
					_id: { $dateToString: { format: "%Y-%m-%d", date: "$bucketStart" } },
					totalRequests: { $sum: { $add: ["$successCount", "$errorCount"] } },
					// Buckets are keyed apiKeyId×bucketStart, so summing docs would
					// count keys (one user × many keys → inflated). Dedupe owners.
					uniqueOwners: { $addToSet: "$ownerId" },
				},
			},
			{ $project: { _id: 1, totalRequests: 1, activeUsers: { $size: "$uniqueOwners" } } },
			{ $sort: { _id: -1 } },
			{ $limit: 30 },
		]);

		return res.status(200).json(standardResponse(true, "Engagement metrics fetched", engagement));
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

		const { from, to } = rawWindow(req);
		const match: Record<string, unknown> = {
			timestamp: { $gte: from, $lte: to },
		};

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

		return res.status(200).json(standardResponse(true, "Feature usage stats fetched", usage));
	} catch (err) {
		next(err);
	}
}

export async function getSubscriptionTrends(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel }: Deps,
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

		return res.status(200).json(standardResponse(true, "Subscription trends fetched", trends));
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
			return res.status(403).json(standardResponse(false, "Only admins can export metrics", null));
		}

		const { format = "json", from, to, cursor, limit = "10000" } = req.query;

		// Record-level export: paginate with an ISO timestamp cursor (docs are
		// sorted timestamp desc; pass the last seen timestamp as ?cursor=).
		const cap = Math.min(parseInt(limit as string, 10) || 1000, 1000);

		const match: Record<string, unknown> = {};
		if (cursor || from || to) {
			const ts: Record<string, Date> = {};
			if (cursor) ts.$lt = new Date(cursor as string);
			if (from) ts.$gte = new Date(from as string);
			if (to) ts.$lte = new Date(to as string);
			match.timestamp = ts;
		}

		const events = await rawEventModel
			.find(match)
			.sort({ timestamp: -1 })
			.limit(cap)
			.lean();

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

		return res.status(200).json(standardResponse(true, "Metrics exported", events));
	} catch (err) {
		next(err);
	}
}

export async function generateReport(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel, Rollup5m, Rollup1h, Rollup1d }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res.status(403).json(standardResponse(false, "Only admins can generate reports", null));
		}

		const { type, from, to } = req.query;
		if (!type || !["usage", "errors", "latency", "growth"].includes(type as string)) {
			return res.status(400).json(standardResponse(false, "type must be one of: usage, errors, latency, growth", null));
		}

		let report: unknown;

		if (type === "usage") {
			// Rollup-backed, site-wide time buckets.
			const end = to ? new Date(to as string) : new Date();
			const start = from ? new Date(from as string) : new Date(end.getTime() - 24 * 60 * 60 * 1000);
			const { tier, model } = selectRollupTier(start, end, { Rollup5m, Rollup1h, Rollup1d });
			report = { tier, buckets: await aggregateBucketsSiteWide(model, start, end) };
		} else if (type === "errors") {
			const { from: f, to: t } = rawWindow(req);
			report = await rawEventModel.aggregate([
				{ $match: { statusClass: { $in: ["4xx", "5xx"] }, timestamp: { $gte: f, $lte: t } } },
				{ $group: { _id: { route: "$route", error: "$error" }, count: { $sum: 1 } } },
				{ $sort: { count: -1 } },
			]);
		} else if (type === "latency") {
			const { from: f, to: t } = rawWindow(req);
			report = await rawEventModel.aggregate([
				{ $match: { timestamp: { $gte: f, $lte: t } } },
				{ $group: { _id: "$route", avgMs: { $avg: "$durationMs" }, maxMs: { $max: "$durationMs" } } },
				{ $sort: { avgMs: -1 } },
			]);
		} else {
			report = await userModel.getStatistics();
		}

		return res.status(200).json(standardResponse(true, `${type} report generated`, report as object));
	} catch (err) {
		next(err);
	}
}
