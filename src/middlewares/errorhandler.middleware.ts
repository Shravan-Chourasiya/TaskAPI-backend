import jwt from "jsonwebtoken";
import multer from "multer";
import type { AppError } from "../types/errors.interface.js";

interface ClassErrReturnType {
	status: number;
	message: string;
	errSrc: string;
}

export function classifyError(err: unknown): ClassErrReturnType {
	const error = err as AppError;

	// Nodemailer
	switch (error.code) {
		case "EAUTH":
			return {
				status: 401,
				message: "Email authentication failed",
				errSrc: "nodemailer:EAUTH",
			};
		case "ECONNECTION":
		case "ETIMEDOUT":
			return {
				status: 503,
				message: "Email service unavailable",
				errSrc: "nodemailer:ECONNECTION",
			};
		case "EENVELOPE":
			return {
				status: 400,
				message: "Invalid email recipients",
				errSrc: "nodemailer:EENVELOPE",
			};
	}

	// Multer
	if (err instanceof multer.MulterError) {
		if (err.code === "LIMIT_FILE_SIZE") {
			return { status: 400, message: `File too large. Maximum size is ${5}MB`, errSrc: "multer:LIMIT_FILE_SIZE" };
		}
		if (err.code === "LIMIT_UNEXPECTED_FILE") {
			return { status: 400, message: "Unexpected file field", errSrc: "multer:LIMIT_UNEXPECTED_FILE" };
		}
		return { status: 400, message: err.message, errSrc: "multer" };
	}

	// JWT
	if (error instanceof jwt.TokenExpiredError) {
		return {
			status: 401,
			message: "Token expired",
			errSrc: "jwt:TokenExpiredError",
		};
	}
	if (error instanceof jwt.JsonWebTokenError) {
		return {
			status: 401,
			message: "Invalid token",
			errSrc: "jwt:JsonWebTokenError",
		};
	}
	if (error instanceof jwt.NotBeforeError) {
		return {
			status: 401,
			message: "Token not active yet",
			errSrc: "jwt:NotBeforeError",
		};
	}

	// bcrypt / crypto
	if (error instanceof TypeError || error instanceof RangeError) {
		return { status: 400, message: "Invalid input", errSrc: "bcrypt" };
	}

	// Mongoose
	if (error.name === "ValidationError") {
		return { status: 400, message: "Validation failed", errSrc: "mongoose" };
	}
	if (error.name === "MongoError") {
		return { status: 500, message: "Database error", errSrc: "mongoose" };
	}

	// Rate Limiter
	if (error.name === "RateLimitError") {
		return {
			status: 429,
			message: "Too many requests",
			errSrc: "rate-limiter",
		};
	}

	// Catch-all
	return { status: 500, message: "Internal server error", errSrc: "unknown" };
}
