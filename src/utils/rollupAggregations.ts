import { Model, Types, type PipelineStage } from "mongoose";
import type {
	IRollupBucket,
	RollupGranularity,
} from "../modules/metrics/types/rollupData.type.js";

type RollupModels = {
	Rollup5m: Model<IRollupBucket>;
	Rollup1h: Model<IRollupBucket>;
	Rollup1d: Model<IRollupBucket>;
};

// ─── Tier selection ────────────────────────────────────────────────────────────
// Duration-only: pick the finest tier whose retention covers the range.
// Moved here from dashboard.controller.ts so site-admin rollup-backed
// controllers can reuse it.
export function selectRollupTier(
	from: Date,
	to: Date,
	models: RollupModels,
): { tier: RollupGranularity; model: Model<IRollupBucket> } {
	const durationMs = to.getTime() - from.getTime();
	const TWO_HOURS = 2 * 60 * 60 * 1000;
	const TWO_DAYS = 2 * 24 * 60 * 60 * 1000;

	if (durationMs <= TWO_HOURS) return { tier: "5m", model: models.Rollup5m };
	if (durationMs <= TWO_DAYS) return { tier: "1h", model: models.Rollup1h };
	return { tier: "1d", model: models.Rollup1d };
}

// ─── Aggregated bucket row ─────────────────────────────────────────────────────
// One row per bucketStart. Durations are summed (never averaged) so callers can
// derive avg per success/error; min/max cover the whole bucket.
export interface BucketAggRow {
	bucketStart: Date;
	successCount: number;
	errorCount: number;
	successDurationSum: number;
	errorDurationSum: number;
	minDuration: number | null;
	maxDuration: number | null;
}

// Shared aggregation stage (differs only in the $match).
function buildPipeline(
	from: Date,
	to: Date,
	match: Record<string, unknown>,
): PipelineStage[] {
	return [
		{ $match: { bucketStart: { $gte: from, $lt: to }, ...match } },
		{
			$group: {
				_id: "$bucketStart",
				successCount: { $sum: "$successCount" },
				errorCount: { $sum: "$errorCount" },
				successDurationSum: { $sum: "$successDurationSum" },
				errorDurationSum: { $sum: "$errorDurationSum" },
				minDuration: { $min: "$minDuration" },
				maxDuration: { $max: "$maxDuration" },
			},
		},
		{ $sort: { _id: 1 } },
		{
			$project: {
				_id: 0,
				bucketStart: "$_id",
				successCount: 1,
				errorCount: 1,
				successDurationSum: 1,
				errorDurationSum: 1,
				minDuration: 1,
				maxDuration: 1,
			},
		},
	];
}

// ─── Site-wide aggregation ─────────────────────────────────────────────────────
// All API keys combined, one row per bucket. Used by site-admin rollup-backed
// aggregate routes (FIX 2). Caller passes a tier-selected model.
export async function aggregateBucketsSiteWide(
	model: Model<IRollupBucket>,
	from: Date,
	to: Date,
): Promise<BucketAggRow[]> {
	return model.aggregate<BucketAggRow>(buildPipeline(from, to, {}));
}

// ─── Per-owner aggregation ─────────────────────────────────────────────────────
// One row per bucketStart across only the given apiKeyIds. Used by the
// dashboard all-keys endpoint (FIX 4).
export async function aggregateBucketsByApiKeys(
	model: Model<IRollupBucket>,
	from: Date,
	to: Date,
	apiKeyIds: (string | Types.ObjectId)[],
): Promise<BucketAggRow[]> {
	return model.aggregate<BucketAggRow>(
		buildPipeline(from, to, { apiKeyId: { $in: apiKeyIds } }),
	);
}
