import { Redis } from "ioredis";
import { redisConfig } from "./redis.config.js";

const redisClient = new Redis(redisConfig);

redisClient.on("connect", () => console.warn("✅ Redis connected"));
redisClient.on("error", (err) => console.error("❌ Redis error:", err.cause));

export { redisClient };
