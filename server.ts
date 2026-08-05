import "dotenv/config";
import { app } from "./src/app.js";
import { config } from "./src/configs/app.config.js";
import { redisClient } from "./src/configs/redis.init.js";

// One bad async error must not kill the whole API for every friend using it.
process.on("unhandledRejection", (reason: unknown, promise: Promise<unknown>) => {
	console.error("UNHANDLED REJECTION — process kept alive:", reason);
});

process.on("uncaughtException", (err: Error) => {
	console.error("UNCAUGHT EXCEPTION — process kept alive:", err);
});

const server = app.listen(config.PORT, () => {
	// eslint-disable-next-line no-console
	console.log(`Server running on http://localhost:${config.PORT}`);
});

// Graceful shutdown — let in-flight requests finish, then close Redis + HTTP.
async function shutdown(signal: string) {
	console.log(`\n${signal} received. Shutting down gracefully...`);
	server.close(async () => {
		try {
			await redisClient.quit();
		} catch (err) {
			console.error("Error closing Redis:", err);
		}
		process.exit(0);
	});
	// Force-exit if connections refuse to drain
	setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));