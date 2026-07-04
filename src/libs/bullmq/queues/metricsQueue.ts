import { Queue } from "bullmq";
import { redisConfig } from "../../../configs/redis.config.js";
import { BULLMQ_CONSTANTS } from "../../../constants.js";

// ============ Queue Configurations ============
const redisConfigForBullMQ = { ...redisConfig, maxRetriesPerRequest: null };
const queueConfig = {
	attempts: 5,
	backoff: {
		type: BULLMQ_CONSTANTS.QUEUE_CONFIG.BACKOFF_TYPE,
		delay: BULLMQ_CONSTANTS.QUEUE_CONFIG.BACKOFF_DELAY,
	},
	removeOnComplete: {
		count: BULLMQ_CONSTANTS.QUEUE_CONFIG.REMOVE_ON_COMPLETE_COUNT,
		age: BULLMQ_CONSTANTS.QUEUE_CONFIG.REMOVE_ON_COMPLETE_AGE,
	},
	removeOnFail: {
		count: BULLMQ_CONSTANTS.QUEUE_CONFIG.REMOVE_ON_FAIL_COUNT,
		age: BULLMQ_CONSTANTS.QUEUE_CONFIG.REMOVE_ON_FAIL_AGE,
	},
};

// ==================================== Queues ====================================
export const metricsQueue = new Queue("metrics", {
	connection: redisConfigForBullMQ,
	defaultJobOptions: queueConfig,
});
