import { Queue } from "bullmq";
import { redisConfig } from "../../../configs/redis.config.js";
import { BULLMQ_CONSTANTS } from "../../../constants.js";

const { QUEUE_NAMES, QUEUE_CONFIG } = BULLMQ_CONSTANTS;

// BullMQ manages its own ioredis connection — strip app-level redis options
// that conflict with BullMQ's internal connection handling.
const { lazyConnect: _lc, maxRetriesPerRequest: _mr, ...baseRedisConfig } = redisConfig as any;
const connection = { ...baseRedisConfig, maxRetriesPerRequest: null };

const defaultJobOptions = {
	attempts: QUEUE_CONFIG.ATTEMPTS,
	backoff: {
		type:  QUEUE_CONFIG.BACKOFF_TYPE,
		delay: QUEUE_CONFIG.BACKOFF_DELAY,
	},
	removeOnComplete: {
		count: QUEUE_CONFIG.REMOVE_ON_COMPLETE_COUNT,
		age:   QUEUE_CONFIG.REMOVE_ON_COMPLETE_AGE,
	},
	removeOnFail: {
		count: QUEUE_CONFIG.REMOVE_ON_FAIL_COUNT,
		age:   QUEUE_CONFIG.REMOVE_ON_FAIL_AGE,
	},
};

export const rollup5mQueue = new Queue(QUEUE_NAMES.ROLLUP_5M, { connection, defaultJobOptions });
export const rollup1hQueue = new Queue(QUEUE_NAMES.ROLLUP_1H, { connection, defaultJobOptions });
export const rollup1dQueue = new Queue(QUEUE_NAMES.ROLLUP_1D, { connection, defaultJobOptions });
