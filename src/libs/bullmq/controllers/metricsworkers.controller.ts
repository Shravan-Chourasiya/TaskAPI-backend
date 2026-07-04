import type { TierProcessorDeps } from "../workers/metricsWorker.js";
import {
	getOrCreateWatermark,
	markWatermarkRunning,
	advanceWatermark,
	markWatermarkFailed,
} from "../../../modules/metrics/models/helpers/watermark.helper.js";

export function createRollupProcessor(deps: TierProcessorDeps) {
	return async (_job: unknown): Promise<void> => {
		const { jobName, watermarkModel } = deps;

		const watermark = await getOrCreateWatermark(watermarkModel, jobName);
		if (!watermark) throw new Error(`Failed to get or create watermark for: ${jobName}`);

		await markWatermarkRunning(watermarkModel, jobName);

		try {
			// TODO: implement per-tier aggregation logic using deps.rawEventModel (5m)
			//       or deps.sourceRollupModel (1h / 1d) → deps.targetRollupModel
			await advanceWatermark(watermarkModel, jobName, new Date(), 0);
		} catch (err: any) {
			await markWatermarkFailed(watermarkModel, jobName, err.message);
			throw err;
		}
	};
}
