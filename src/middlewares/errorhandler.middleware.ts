import jwt from "jsonwebtoken";
import type { AppError } from "../modules/auth/types/errors.interface.js";

export function classifyError(err: unknown): {
	status: number;
	message: string;
} {
	const error = err as AppError;

	// Nodemailer
	switch (error.code) {
		case "EAUTH":
			return { status: 401, message: "Email authentication failed" };
		case "ECONNECTION":
		case "ETIMEDOUT":
			return { status: 503, message: "Email service unavailable" };
		case "EENVELOPE":
			return { status: 400, message: "Invalid email recipients" };
	}

	// JWT
	if (error instanceof jwt.TokenExpiredError) {
		return { status: 401, message: "Token expired" };
	}
	if (error instanceof jwt.JsonWebTokenError) {
		return { status: 401, message: "Invalid token" };
	}
	if (error instanceof jwt.NotBeforeError) {
		return { status: 401, message: "Token not active yet" };
	}

	// bcrypt / crypto
	if (error instanceof TypeError || error instanceof RangeError) {
		return { status: 400, message: "Invalid input" };
	}

	// Mongoose
	if (error.name === "ValidationError") {
		return { status: 400, message: "Validation failed" };
	}
	if (error.name === "MongoError") {
		return { status: 500, message: "Database error" };
	}

	// Rate Limiter
	if (error.name === "RateLimitError") {
		return { status: 429, message: "Too many requests" };
	}

	// Catch-all
	return { status: 500, message: "Internal server error" };
}
