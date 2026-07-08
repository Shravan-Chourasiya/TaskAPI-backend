import { Worker } from "bullmq";
import { Model } from "mongoose";
import { redisConfig } from "../../../configs/redis.config.js";
import { BULLMQ_CONSTANTS } from "../../../constants.js";
import type { IRollupWatermark, RollupJobName } from "../../../modules/metrics/types/watermark.type.js";
import type { IRollupBucket } from "../../../modules/metrics/types/rollupData.type.js";
import type { RawEventDocument } from "../../../modules/metrics/types/rawEvent.type.js";

const { WORKER_CONFIG, QUEUE_NAMES, WORKER_NAMES, ROLLUP_JOB_NAMES } = BULLMQ_CONSTANTS;

// Strip app-level redis options that conflict with BullMQ's internal connection
const { lazyConnect: _lc, maxRetriesPerRequest: _mr, ...baseRedisConfig } = redisConfig as any;
const bullmqConnection = { ...baseRedisConfig, maxRetriesPerRequest: null };

// ─── Processor deps ───────────────────────────────────────────────────────────
// Each tier receives only the models it actually needs.
// 5m: reads rawEventModel  → writes targetRollupModel
// 1h: reads sourceRollupModel (5m) → writes targetRollupModel
// 1d: reads sourceRollupModel (1h) → writes targetRollupModel

export interface TierProcessorDeps {
	jobName:            RollupJobName;
	watermarkModel:     Model<IRollupWatermark>;
	targetRollupModel:  Model<IRollupBucket>;
	rawEventModel?:     Model<RawEventDocument>;   // 5m tier only
	sourceRollupModel?: Model<IRollupBucket>;       // 1h / 1d tiers only
}

type ProcessorFactory = (deps: TierProcessorDeps) => (job: unknown) => Promise<void>;

// ─── Shared worker factory ────────────────────────────────────────────────────

interface TierWorkerConfig {
	queueName:        string;
	workerName:       string;
	processorFactory: ProcessorFactory;
	deps:             TierProcessorDeps;
}

function initTierWorker({ queueName, workerName, processorFactory, deps }: TierWorkerConfig): Worker {
	const worker = new Worker(queueName, processorFactory(deps), {
		connection:       bullmqConnection,
		name:             workerName,
		concurrency:      WORKER_CONFIG.CONCURRENCY,
		removeOnComplete: { count: WORKER_CONFIG.REMOVE_ON_COMPLETE_LIMIT },
		removeOnFail:     { count: WORKER_CONFIG.REMOVE_ON_FAIL_LIMIT },
		stalledInterval:  WORKER_CONFIG.STALLED_INTERVAL_MS,
		maxStalledCount:  WORKER_CONFIG.MAX_STALLED_COUNT,
	});

	worker.on("completed", (job) =>
		console.info(`[${workerName}] job ${job.id} completed`),
	);
	worker.on("failed", (job, err) =>
		console.error(`[${workerName}] job ${job?.id} failed:`, err.message),
	);
	worker.on("error", (err) =>
		console.error(`[${workerName}] worker error:`, err.message),
	);

	return worker;
}

// ─── 3-tier boot ─────────────────────────────────────────────────────────────

export interface RollupWorkerModels {
	watermarkModel:    Model<IRollupWatermark>;
	rawEventModel:     Model<RawEventDocument>;
	rollup5mModel:     Model<IRollupBucket>;
	rollup1hModel:     Model<IRollupBucket>;
	rollup1dModel:     Model<IRollupBucket>;
}

export function initRollupWorkers(
	models: RollupWorkerModels,
	processorFactory: ProcessorFactory,
): Worker[] {
	const { watermarkModel, rawEventModel, rollup5mModel, rollup1hModel, rollup1dModel } = models;

	return [
		initTierWorker({
			queueName:        QUEUE_NAMES.ROLLUP_5M,
			workerName:       WORKER_NAMES.ROLLUP_5M,
			processorFactory,
			deps: {
				jobName:           ROLLUP_JOB_NAMES.ROLLUP_5M,
				watermarkModel,
				rawEventModel,
				targetRollupModel: rollup5mModel,
			},
		}),
		initTierWorker({
			queueName:        QUEUE_NAMES.ROLLUP_1H,
			workerName:       WORKER_NAMES.ROLLUP_1H,
			processorFactory,
			deps: {
				jobName:            ROLLUP_JOB_NAMES.ROLLUP_1H,
				watermarkModel,
				sourceRollupModel:  rollup5mModel,
				targetRollupModel:  rollup1hModel,
			},
		}),
		initTierWorker({
			queueName:        QUEUE_NAMES.ROLLUP_1D,
			workerName:       WORKER_NAMES.ROLLUP_1D,
			processorFactory,
			deps: {
				jobName:            ROLLUP_JOB_NAMES.ROLLUP_1D,
				watermarkModel,
				sourceRollupModel:  rollup1hModel,
				targetRollupModel:  rollup1dModel,
			},
		}),
	];
}
