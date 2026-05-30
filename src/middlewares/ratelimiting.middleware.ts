// import rateLimit, { ipKeyGenerator } from "express-rate-limit";
// import type { Request } from "express";

// type RequestWithUser = Request & {
// 	userID?: string;
// };

// export const rateLimitMiddleware = rateLimit({
// 	windowMs: 10 * 60 * 1000, // 10 minutes
// 	limit: 50,
// 	standardHeaders: "draft-7",
// 	legacyHeaders: false,
// 	keyGenerator: (req: RequestWithUser) => {
// 		const userID = req.userID;
// 		const ipKey = ipKeyGenerator(req.ip as string);
// 		return userID ? `${userID}-${ipKey}` : ipKey;
// 	},
// });

// export const otpRateLimiter = rateLimit({
// 	windowMs: 5 * 60 * 1000,
// 	max: 3,
// 	message: "Too many OTP attempts. Try again after 10 minutes.",
// 	keyGenerator: (req) => {
// 		const email = req.body.email || req.cookies.tempToken;
// 		return email || ipKeyGenerator(req.ip || ""); // Fallback to IP
// 	},
// });

import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import RedisStore, {
	type RedisReply,
	type SendCommandFn,
} from "rate-limit-redis";
import type { Request, Response } from "express";
import { redisClient } from "../configs/redis.init.js";
import crypto from "crypto";
import constants from "../constants.js";
import { REDIS_PREFIXES } from "../constants.js";

type RequestWithUser = Request & {
	userID?: string;
};

// Hash email for privacy in Redis keys
const hashEmail = (email: string): string => {
	return crypto
		.createHash("sha256")
		.update(email.toLowerCase())
		.digest("hex")
		.substring(0, 16);
};

// Custom Redis command sender for rate-limit-redis
const sendCommand: SendCommandFn = (command: string, ...args: string[]) =>
	redisClient.call(command, ...args) as Promise<RedisReply>;

// Custom error handler
const rateLimitHandler = (req: Request, res: Response) => {
	res.status(429).json({
		success: false,
		error: "Too many requests",
		message: "You have exceeded the rate limit. Please try again later.",
		retryAfter: res.getHeader("Retry-After"),
	});
};

// ============ GENERAL API RATE LIMITER ============
export const apiRateLimiter = rateLimit({
	windowMs: constants.GENERAL_RL_TIME_WINDOW_MS, // 15 minutes
	limit: constants.GENERAL_API_RATE_LIMIT_MAX, // 100 requests per 15 min
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: REDIS_PREFIXES.RATE_LIMIT_API,
	}),
	keyGenerator: (req: RequestWithUser) => {
		const userID = req.userID;
		const ip = ipKeyGenerator((req.ip as string) || "unknown");
		return userID ? `user:${userID}` : `ip:${ip}`;
	},
	handler: rateLimitHandler,
	skip: (req) => req.method === "OPTIONS", // Skip preflight
});

// ============ AUTH RATE LIMITER (Login/Register) ============
export const authRateLimiter = rateLimit({
	windowMs: constants.AUTH_RL_TIME_WINDOW_MS, // 10 minutes
	limit: constants.AUTH_RATE_LIMIT_MAX,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: REDIS_PREFIXES.RATE_LIMIT_AUTH,
	}),
	keyGenerator: (req) => {
		const email = req.body.email?.toLowerCase();
		const ip = ipKeyGenerator((req.ip as string) || "unknown");
		return email ? `email:${hashEmail(email)}` : `ip:${ip}`;
	},
	handler: rateLimitHandler,
	skipSuccessfulRequests: true, // Only count failed login attempts
});

// ============ OTP GENERATION RATE LIMITER ============
export const otpGenerationLimiter = rateLimit({
	windowMs: constants.OTP_RL_TIME_WINDOW_MS, // 10 minutes
	limit: constants.OTP_RATE_LIMIT_MAX, // 3 OTP requests per 10 min
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: REDIS_PREFIXES.RATE_LIMIT_OTP_GEN,
	}),
	keyGenerator: (req) => {
		const email = req.body.email?.toLowerCase();
		const ip = ipKeyGenerator((req.ip as string) || "unknown");
		return email ? `email:${hashEmail(email)}` : `ip:${ip}`;
	},
	handler: rateLimitHandler,
	skipFailedRequests: true, // Only count successful OTP generations
});

// ============ OTP VERIFICATION RATE LIMITER ============
export const otpVerificationLimiter = rateLimit({
	windowMs: constants.OTP_RL_TIME_WINDOW_MS, // 10 minutes
	limit: constants.OTP_RATE_LIMIT_MAX, // 5 verification attempts per 10 min
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: REDIS_PREFIXES.RATE_LIMIT_OTP_VERIFY,
	}),
	keyGenerator: (req) => {
		const email = req.body.email?.toLowerCase();
		const ip = ipKeyGenerator((req.ip as string) || "unknown");
		return email ? `email:${hashEmail(email)}` : `ip:${ip}`;
	},
	handler: rateLimitHandler,
	skipSuccessfulRequests: true, // Only count failed verifications
});

export const profileUpdateLimiter = rateLimit({
	windowMs: constants.UPDATE_RL_TIME_WINDOW_MS, // 2 minutes
	limit: constants.UPDATE_RATE_LIMIT_MAX, // 1 profile update request per 2 min
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: REDIS_PREFIXES.RATE_LIMIT_UPDATE,
	}),
	keyGenerator: (req) => {
		const email = req.body.email?.toLowerCase();
		const ip = ipKeyGenerator((req.ip as string) || "unknown");
		return email ? `email:${hashEmail(email)}` : `ip:${ip}`;
	},
	handler: rateLimitHandler,
	skipFailedRequests: true, // Only count successful profile updates
});