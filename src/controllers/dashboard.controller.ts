import type { NextFunction, Request, Response } from "express";
import { Model } from "mongoose";
import jwt, { JwtPayload } from "jsonwebtoken";
import { config } from "../configs/app.config.js";
import { standardResponse } from "../utils/apiResponse.utils.js";
import { UserStaticMethods } from "../types/mongoModels/user.type.js";
import { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import { ClientUserStaticMethods } from "../modules/clientauth/types/userMongo.type.js";
import {
	IRollupBucket,
} from "../modules/metrics/types/rollupData.type.js";
import {
	selectRollupTier,
	aggregateBucketsByApiKeys,
} from "../utils/rollupAggregations.js";

type RollupModels = {
	Rollup5m: Model<IRollupBucket>;
	Rollup1h: Model<IRollupBucket>;
	Rollup1d: Model<IRollupBucket>;
};

// ── Shared auth helper ────────────────────────────────────────────────────────
async function resolveUser(
	req: Request,
	res: Response,
	userModel: UserStaticMethods,
) {
	if (!req.cookies.acToken || req.cookies.acToken === "") {
		res.status(401).json(standardResponse(false, "Missing access token."));
		return null;
	}

	let decoded: JwtPayload;
	try {
		decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
	} catch {
		res
			.status(401)
			.json(standardResponse(false, "Invalid or expired access token."));
		return null;
	}

	const user = await userModel.findById(decoded.id);
	if (!user) {
		res.status(404).json(standardResponse(false, "User not found."));
		return null;
	}

	return user;
}

// ── Shared time-range parser ──────────────────────────────────────────────────
function parseTimeRange(
	req: Request,
	res: Response,
): { from: Date; to: Date } | null {
	const { from: fromStr, to: toStr } = req.query as Record<string, string>;

	if (!fromStr || !toStr) {
		res
			.status(400)
			.json(
				standardResponse(false, "Query params 'from' and 'to' are required."),
			);
		return null;
	}

	const from = new Date(fromStr);
	const to = new Date(toStr);

	if (isNaN(from.getTime()) || isNaN(to.getTime())) {
		res
			.status(400)
			.json(
				standardResponse(
					false,
					"'from' and 'to' must be valid ISO date strings.",
				),
			);
		return null;
	}

	if (from >= to) {
		res
			.status(400)
			.json(standardResponse(false, "'from' must be before 'to'."));
		return null;
	}

	return { from, to };
}

// ── Controller params type ────────────────────────────────────────────────────
type ControllerDeps = {
	userModel: UserStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
	clientUserModel: ClientUserStaticMethods;
	Rollup5m: Model<IRollupBucket>;
	Rollup1h: Model<IRollupBucket>;
	Rollup1d: Model<IRollupBucket>;
};

// ── All-keys controller ───────────────────────────────────────────────────────
export async function getAllApiMetricsController(
	req: Request,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel, Rollup5m, Rollup1h, Rollup1d }: ControllerDeps,
) {
	try {
		const user = await resolveUser(req, res, userModel);
		if (!user) return;

		const range = parseTimeRange(req, res);
		if (!range) return;

		const { from, to } = range;

		const apiKeys = await apiKeyModel
			.find({ userId: String(user._id) })
			.select("_id")
			.lean();
		if (!apiKeys.length) {
			return res
				.status(404)
				.json(standardResponse(false, "No API keys found for this user."));
		}
		const apiKeyIds = apiKeys.map((k) => k._id);
		const { tier, model } = selectRollupTier(from, to, {
			Rollup5m,
			Rollup1h,
			Rollup1d,
		});
		// Single aggregation across the owner's keys, grouped per bucketStart.
		// Bounds response size to the bucket count, independent of key count.
		const buckets = await aggregateBucketsByApiKeys(model, from, to, apiKeyIds);
		return res.status(200).json(
			standardResponse(true, "Metrics fetched successfully.", {
				tier,
				buckets,
			}),
		);
	} catch (err) {
		next(err);
	}
}

// ── Specific-key controller ───────────────────────────────────────────────────
export async function getSpecificApiMetricsController(
	req: Request,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel, Rollup5m, Rollup1h, Rollup1d }: ControllerDeps,
) {
	try {
		const apiId = req.params.keyId;
		if (!apiId) {
			return res
				.status(400)
				.json(standardResponse(false, "API key ID is required in the URL."));
		}

		const user = await resolveUser(req, res, userModel);
		if (!user) return;

		// Ownership check — 403 to avoid leaking existence of keys not owned by caller
		// Ensure IDs are strings to satisfy mongoose typings
		const apiKey = await apiKeyModel.findOne({ _id: String(apiId), userId: String(user._id) });
		if (!apiKey) {
			return res.status(403).json(standardResponse(false, "Forbidden."));
		}

		const range = parseTimeRange(req, res);
		if (!range) return;

		// Clamp 'from' to apiKey.createdAt if range starts before the key existed
		const from = range.from < apiKey.createdAt ? apiKey.createdAt : range.from;
		const to = range.to;

		if (from >= to) {
			return res
				.status(400)
				.json(
					standardResponse(
						false,
						"Requested range is entirely before this API key was created.",
					),
				);
		}

		const { tier, model } = selectRollupTier(from, to, {
			Rollup5m,
			Rollup1h,
			Rollup1d,
		});

		const buckets = await model
			.find({ apiKeyId: apiId, bucketStart: { $gte: from, $lt: to } })
			.sort({ bucketStart: 1 })
			.lean();

		return res
			.status(200)
			.json(
				standardResponse(true, "Metrics fetched successfully.", {
					tier,
					buckets,
				}),
			);
	} catch (err) {
		next(err);
	}
}
