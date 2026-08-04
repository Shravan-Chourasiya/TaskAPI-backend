import { Model } from "mongoose";
import type { IRollupBucket } from "../../../modules/metrics/types/rollupData.type.js";
import { alignToBucket } from "../../../utils/bucketAlign.js";
import { BULLMQ_CONSTANTS } from "../../../constants.js";

export async function aggregateRollupTier(
	sourceRollupModel: Model<IRollupBucket>,
	targetRollupModel: Model<IRollupBucket>,
	targetGranularity: "1h" | "1d",
	windowStart: Date,
	windowEnd: Date,
): Promise<number> {
	const sourceBuckets = await sourceRollupModel
		.find({ bucketStart: { $gte: windowStart, $lt: windowEnd } })
		.lean();

	if (sourceBuckets.length === 0) return 0;

	// IDEMPOTENCY: buckets are written with replaceOne (full-document upsert)
	// keyed on (apiKeyId, bucketStart), not $inc. A retry after a crash re-derives
	// the same window and overwrites buckets with identical values, so
	// reprocessing can never double-count.

	const grouped = new Map<string, {
		apiKeyId: any;
		ownerId: string;
		bucketStart: Date;
		successCount: number;
		errorCount: number;
		successDurationSum: number;
		errorDurationSum: number;
		minDuration: number;
		maxDuration: number;
	}>();

	for (const b of sourceBuckets) {
		const bucketStart = alignToBucket(b.bucketStart, targetGranularity);
		const key = `${b.apiKeyId}_${b.ownerId}_${bucketStart.getTime()}`;

		if (!grouped.has(key)) {
			grouped.set(key, {
				apiKeyId: b.apiKeyId,
				ownerId: b.ownerId,
				bucketStart,
				successCount: 0,
				errorCount: 0,
				successDurationSum: 0,
				errorDurationSum: 0,
				minDuration: b.minDuration,
				maxDuration: b.maxDuration,
			});
		}

		const g = grouped.get(key)!;
		g.successCount       += b.successCount;
		g.errorCount         += b.errorCount;
		g.successDurationSum += b.successDurationSum;
		g.errorDurationSum   += b.errorDurationSum;
		g.minDuration = Math.min(g.minDuration, b.minDuration);
		g.maxDuration = Math.max(g.maxDuration, b.maxDuration);
	}

	const retentionMs = BULLMQ_CONSTANTS.RETENTION_MS[targetGranularity];

	const ops = Array.from(grouped.values()).map((g) => ({
		replaceOne: {
			filter: { apiKeyId: g.apiKeyId, bucketStart: g.bucketStart },
			replacement: {
				apiKeyId: g.apiKeyId,
				ownerId: g.ownerId,
				bucketStart: g.bucketStart,
				granularity: targetGranularity,
				successCount: g.successCount,
				errorCount: g.errorCount,
				successDurationSum: g.successDurationSum,
				errorDurationSum: g.errorDurationSum,
				minDuration: g.minDuration,
				maxDuration: g.maxDuration,
				expiresAt: new Date(g.bucketStart.getTime() + retentionMs),
			},
			upsert: true, // create the bucket when it doesn't exist yet
		},
	}));

	await targetRollupModel.bulkWrite(ops, { ordered: false });
	return sourceBuckets.length;
}
