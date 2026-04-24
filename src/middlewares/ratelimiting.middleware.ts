import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import type { Request } from "express";

type RequestWithUser = Request & {
	userID?: string;
};

export const rateLimitMiddleware = rateLimit({
	windowMs: 10 * 60 * 1000, // 10 minutes
	limit: 50,
	standardHeaders: "draft-7",
	legacyHeaders: false,
	keyGenerator: (req: RequestWithUser) => {
		const userID = req.userID;
		const ipKey = ipKeyGenerator(req.ip as string);
		return userID ? `${userID}-${ipKey}` : ipKey;
	},
});

export const otpRateLimiter = rateLimit({
	windowMs: 10 * 60 * 1000,
	max: 5,
	message: "Too many OTP attempts. Try again after 10 minutes.",
	keyGenerator: (req) => {
		const email = req.body.email || req.cookies.tempToken;
		return email || ipKeyGenerator(req.ip || ""); // Fallback to IP
	},
});
