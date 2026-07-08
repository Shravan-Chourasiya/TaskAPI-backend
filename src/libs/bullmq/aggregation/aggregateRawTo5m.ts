import { Model, Types } from "mongoose";
import type { RawEventDocument } from "../../../modules/metrics/types/rawEvent.type.js";
import type { IRollupBucket } from "../../../modules/metrics/types/rollupData.type.js";
import { alignToBucket } from "../../../utils/bucketAlign.js";
import { BULLMQ_CONSTANTS } from "../../../constants.js";

const RETENTION_5M_MS = BULLMQ_CONSTANTS.RETENTION_MS["5m"];

export async function aggregateRawTo5m(
	rawEventModel: Model<RawEventDocument>,
	targetRollupModel: Model<IRollupBucket>,
	windowStart: Date,
	windowEnd: Date,
): Promise<number> {
	const events = await rawEventModel
		.find({ timestamp: { $gte: windowStart, $lt: windowEnd } })
		.lean();

	if (events.length === 0) return 0;

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

	for (const ev of events) {
		const bucketStart = alignToBucket(ev.timestamp, "5m");
		const key = `${ev.apiKeyId}_${bucketStart.getTime()}`;

		const apiKeyObjectId = new Types.ObjectId(ev.apiKeyId);
		if (!grouped.has(key)) {
			grouped.set(key, {
				apiKeyId: apiKeyObjectId,
				bucketStart,
				successCount: 0,
				errorCount: 0,
				successDurationSum: 0,
				errorDurationSum: 0,
				minDuration: ev.durationMs,
				maxDuration: ev.durationMs,
			});
		}

		const g = grouped.get(key)!;
		const isSuccess = ev.httpStatusCode < 400;
		if (isSuccess) {
			g.successCount += 1;
			g.successDurationSum += ev.durationMs;
		} else {
			g.errorCount += 1;
			g.errorDurationSum += ev.durationMs;
		}
		g.minDuration = Math.min(g.minDuration, ev.durationMs);
		g.maxDuration = Math.max(g.maxDuration, ev.durationMs);
	}

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
					granularity: "5m",
					expiresAt: new Date(g.bucketStart.getTime() + RETENTION_5M_MS),
				},
			},
			upsert: true,
		},
	}));

	await targetRollupModel.bulkWrite(ops, { ordered: false });
	return events.length;
}
