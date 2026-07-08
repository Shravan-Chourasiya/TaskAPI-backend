import type { TierProcessorDeps } from "../workers/metricsWorker.js";
import {
	getOrCreateWatermark,
	markWatermarkRunning,
	advanceWatermark,
	markWatermarkFailed,
} from "../../../modules/metrics/models/helpers/watermark.helper.js";
import { aggregateRawTo5m } from "../aggregation/aggregateRawTo5m.js";
import { aggregateRollupTier } from "../aggregation/aggregateRollupTier.js";
import { windowEnd } from "../../../utils/bucketAlign.js";
import { BULLMQ_CONSTANTS } from "../../../constants.js";

export function createRollupProcessor(deps: TierProcessorDeps) {
	return async (_job: unknown): Promise<void> => {
		const { jobName, watermarkModel } = deps;
		const startedAt = Date.now();

		const watermark = await getOrCreateWatermark(watermarkModel, jobName);
		if (!watermark) throw new Error(`Failed to get or create watermark for: ${jobName}`);

		await markWatermarkRunning(watermarkModel, jobName);

		const windowStart = watermark.lastProcessedAt;
		const windowEndDate = windowEnd(new Date(), BULLMQ_CONSTANTS.SAFETY_BUFFER_MS);

		if (windowStart >= windowEndDate) {
			// Nothing new yet — reset status to idle without moving the cursor
			await advanceWatermark(watermarkModel, jobName, windowStart, 0);
			return;
		}

		try {
			let processedCount = 0;

			if (jobName === "rollup_5m") {
				processedCount = await aggregateRawTo5m(
					deps.rawEventModel!,
					deps.targetRollupModel,
					windowStart,
					windowEndDate,
				);
			} else {
				const targetGranularity = jobName === "rollup_1h" ? "1h" : "1d";
				processedCount = await aggregateRollupTier(
					deps.sourceRollupModel!,
					deps.targetRollupModel,
					targetGranularity,
					windowStart,
					windowEndDate,
				);
			}

			const durationMs = Date.now() - startedAt;
			await advanceWatermark(watermarkModel, jobName, windowEndDate, durationMs);
			console.info(`[${jobName}] processed ${processedCount} docs in ${durationMs}ms`);
		} catch (err: any) {
			await markWatermarkFailed(watermarkModel, jobName, err.message);
			throw err;
		}
	};
}
