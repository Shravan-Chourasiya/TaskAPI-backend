import type { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../configs/app.config.js";
import { SessionStaticMethods } from "../types/mongoModels/session.type.js";
import { tokenMiddlewareResponse } from "../utils/apiResponse.utils.js";

type RequestWithSession = Request & { sessionId?: string };

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// ── Token generation ──────────────────────────────────────────────────────────
// 32 bytes → 64 char hex string, cryptographically random
export function generateCsrfToken(): string {
	return crypto.randomBytes(32).toString("hex");
}

// ── Middleware factory ────────────────────────────────────────────────────────
export function createCsrfMiddleware(sessionModel: SessionStaticMethods) {
	return async function csrfProtection(
		req: RequestWithSession,
		res: Response,
		next: NextFunction,
	) {
		if (!MUTATING_METHODS.has(req.method)) return next();

		const tokenFromHeader = req.headers["x-csrf-token"];
		const hasSessionCookie = Boolean(req.cookies?.acToken);

		if (!req.sessionId && hasSessionCookie) {
			try {
				const decoded = jwt.verify(
					req.cookies.acToken,
					config.ACCESS_TOKEN_JWT_SECRET,
				) as JwtPayload;
				if (decoded?.sessionId) {
					req.sessionId = decoded.sessionId as string;
				}
			} catch {
				// Ignore invalid token and let the downstream auth middleware handle it
			}
		}

		if (!tokenFromHeader || typeof tokenFromHeader !== "string") {
			if (!req.sessionId) {
				return next();
			}
			return res
				.status(403)
				.json(
					tokenMiddlewareResponse(
						false,
						"CSRF token missing",
						"CsrfMissing",
						false,
					),
				);
		}

		if (!req.sessionId) {
			return res
				.status(401)
				.json(
					tokenMiddlewareResponse(
						false,
						"No active session",
						"Unauthorized",
						true,
					),
				);
		}

		const session = await sessionModel
			.findById(req.sessionId)
			.select("+csrfToken");

		if (!session?.csrfToken) {
			return res
				.status(403)
				.json(
					tokenMiddlewareResponse(
						false,
						"CSRF token not found in session",
						"CsrfInvalid",
						false,
					),
				);
		}

		// Constant-time comparison — prevents timing attacks
		const expected = Buffer.from(session.csrfToken, "hex");
		const received = Buffer.from(tokenFromHeader, "hex");

		const isValid =
			expected.length === received.length &&
			crypto.timingSafeEqual(expected, received);

		if (!isValid) {
			return res
				.status(403)
				.json(
					tokenMiddlewareResponse(
						false,
						"Invalid CSRF token",
						"CsrfInvalid",
						false,
					),
				);
		}

		next();
	};
}
