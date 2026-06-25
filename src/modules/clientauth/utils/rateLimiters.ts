import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import RedisStore, {
	type RedisReply,
	type SendCommandFn,
} from "rate-limit-redis";
import type { Request, Response } from "express";
import { redisClient } from "../../../configs/redis.init.js";
import crypto from "crypto";
import { CLIENT_REDIS_PREFIXES } from "../../../constants.js";

const hashValue = (value: string): string =>
	crypto
		.createHash("sha256")
		.update(value.toLowerCase())
		.digest("hex")
		.substring(0, 16);

const sendCommand: SendCommandFn = (command: string, ...args: string[]) =>
	redisClient.call(command, ...args) as Promise<RedisReply>;

const rateLimitHandler = (req: Request, res: Response) => {
	res.status(429).json({
		success: false,
		error: "TooManyRequests",
		message: "Rate limit exceeded. Please try again later.",
		retryAfter: res.getHeader("Retry-After"),
	});
};

// Primary key = hashed API key, fallback = IP
const apiKeyGenerator = (req: Request): string => {
	const apiKey = req.headers["x-api-key"] as string | undefined;
	const ip = ipKeyGenerator((req.ip as string) || "unknown");
	return apiKey ? `apikey:${hashValue(apiKey)}` : `ip:${ip}`;
};

// Per API key + per email — scopes limits to each client app's individual users
const apiKeyEmailGenerator = (req: Request): string => {
	const apiKey = req.headers["x-api-key"] as string | undefined;
	const email = req.body?.email?.toLowerCase();
	const ip = ipKeyGenerator((req.ip as string) || "unknown");
	if (apiKey && email) return `apikey:${hashValue(apiKey)}:email:${hashValue(email)}`;
	if (apiKey) return `apikey:${hashValue(apiKey)}`;
	return `ip:${ip}`;
};

// ============ CLIENT GENERAL API RATE LIMITER ============
export const clientApiRateLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 200,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: CLIENT_REDIS_PREFIXES.RATE_LIMIT_GENERAL_API,
	}),
	keyGenerator: apiKeyGenerator,
	handler: rateLimitHandler,
	skip: (req) => req.method === "OPTIONS",
});

// ============ CLIENT AUTH RATE LIMITER (Login / Register) ============
// skipSuccessfulRequests: only failed attempts count toward the limit
export const clientAuthRateLimiter = rateLimit({
	windowMs: 10 * 60 * 1000,
	limit: 8,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: CLIENT_REDIS_PREFIXES.RATE_LIMIT_AUTH,
	}),
	keyGenerator: apiKeyEmailGenerator,
	handler: rateLimitHandler,
	skipSuccessfulRequests: true,
});

// ============ CLIENT OTP GENERATION RATE LIMITER ============
export const clientOtpGenerationLimiter = rateLimit({
	windowMs: 10 * 60 * 1000,
	limit: 3,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: CLIENT_REDIS_PREFIXES.RATE_LIMIT_OTP_GENERATION,
	}),
	keyGenerator: apiKeyEmailGenerator,
	handler: rateLimitHandler,
});

// ============ CLIENT OTP VERIFICATION RATE LIMITER ============
// skipSuccessfulRequests: only failed verifications count
export const clientOtpVerificationLimiter = rateLimit({
	windowMs: 10 * 60 * 1000,
	limit: 5,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: CLIENT_REDIS_PREFIXES.RATE_LIMIT_OTP_VERIFICATION,
	}),
	keyGenerator: apiKeyEmailGenerator,
	handler: rateLimitHandler,
	skipSuccessfulRequests: true,
});

// ============ CLIENT PROFILE UPDATE RATE LIMITER ============
// User is authenticated so no email needed — scoped per API key only
export const clientProfileUpdateLimiter = rateLimit({
	windowMs: 5 * 60 * 1000,
	limit: 3,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	store: new RedisStore({
		sendCommand,
		prefix: CLIENT_REDIS_PREFIXES.RATE_LIMIT_PROFILE_UPDATE,
	}),
	keyGenerator: apiKeyGenerator,
	handler: rateLimitHandler,
	skipFailedRequests: true,
});
