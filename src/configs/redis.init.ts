import { Redis } from "ioredis";
import { redisConfig } from "./redis.config.js";
import { logger } from "../utils/logger.utils.js";

const redisClient = new Redis(redisConfig);

redisClient.on("connect", () => logger.info("✅ Redis connected"));
redisClient.on("error", (err) => logger.error("❌ Redis error:", { cause: err.cause }));

export { redisClient };
