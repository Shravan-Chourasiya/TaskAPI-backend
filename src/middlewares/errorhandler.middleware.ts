import jwt from "jsonwebtoken";
import multer from "multer";
import type { ErrorRequestHandler } from "express";
import { AppError } from "../types/errors.interface.js";

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
	if (
		error.name === "MongoError" ||
		error.name === "MongoServerError" ||
		error.name === "MongoBulkWriteError"
	) {
		// Duplicate key (E11000) on unique index — e.g. email/username races.
		const mongoError = error as unknown as { code?: number };
		if (mongoError.code === 11000) {
			return {
				status: 409,
				message: "Duplicate value for a unique field",
				errSrc: "mongoose:duplicate-key",
			};
		}
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
	return { status: 500, message: "Internal server error", errSrc: "INTERNAL_ERROR" };
}

/**
 * Centralized Express error middleware. Sends the response for any error
 * routed here via next(err) (from asyncErrorHandler or direct throw in sync
 * middleware) and stamps the machine-readable error code onto res.locals so
 * the metrics collector can persist it into the raw event's `error` field.
 *
 * `code` is the AppError.code when present, otherwise the classifyError
 * errSrc for known errors, otherwise a generic INTERNAL_ERROR.
 *
 * Must be registered AFTER all routes — Express skips it otherwise.
 */
export const errorHandler: ErrorRequestHandler = (
	err,
	_req,
	res,
	_next,
): void => {
	const { status, message, errSrc } = classifyError(err);
	res.locals.errorCode = AppError.isAppError(err) ? err.code : errSrc;

	// Log server errors
	if (status >= 500) {
		console.error(`[${errSrc}] Server error:`, err);
		// TODO: Replace with proper logging mechanism (Winston, Pino, etc.)
	}

	// Only send if headers not already sent — protects the finish/close flow.
	if (!res.headersSent) {
		res.status(status).json({
			success: false,
			error: errSrc,
			message,
		});
	}
};
