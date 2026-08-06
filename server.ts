import "dotenv/config";
import { app } from "./src/app.js";
import { config } from "./src/configs/app.config.js";
import { redisClient } from "./src/configs/redis.init.js";
import { logger } from "./src/utils/logger.utils.js";

// One bad async error must not kill the whole API for every friend using it.
process.on("unhandledRejection", (reason: unknown, promise: Promise<unknown>) => {
	logger.error("UNHANDLED REJECTION — process kept alive:", { reason });
});

process.on("uncaughtException", (err: Error) => {
	logger.error("UNCAUGHT EXCEPTION — process kept alive:", {
		message: err.message,
		stack: err.stack,
	});
});

const server = app.listen(config.PORT, () => {
	logger.info(`Server running on http://localhost:${config.PORT}`);
});

// Graceful shutdown — let in-flight requests finish, then close Redis + HTTP.
async function shutdown(signal: string) {
	logger.info(`\n${signal} received. Shutting down gracefully...`);
	server.close(async () => {
		try {
			await redisClient.quit();
		} catch (err) {
			logger.error("Error closing Redis:", { err });
		}
		process.exit(0);
	});
	// Force-exit if connections refuse to drain
	setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));