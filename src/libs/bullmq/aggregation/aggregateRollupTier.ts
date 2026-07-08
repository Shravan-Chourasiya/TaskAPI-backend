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

	const grouped = new Map<string, {
		apiKeyId: any;
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
		const key = `${b.apiKeyId}_${bucketStart.getTime()}`;

		if (!grouped.has(key)) {
			grouped.set(key, {
				apiKeyId: b.apiKeyId,
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
		updateOne: {
			filter: { apiKeyId: g.apiKeyId, bucketStart: g.bucketStart },
			update: {
				$inc: {
					successCount:       g.successCount,
					errorCount:         g.errorCount,
					successDurationSum: g.successDurationSum,
					errorDurationSum:   g.errorDurationSum,
				},
				$min: { minDuration: g.minDuration },
				$max: { maxDuration: g.maxDuration },
				$setOnInsert: {
					granularity: targetGranularity,
					expiresAt: new Date(g.bucketStart.getTime() + retentionMs),
				},
			},
			upsert: true,
		},
	}));

	await targetRollupModel.bulkWrite(ops, { ordered: false });
	return sourceBuckets.length;
}
