import type { NextFunction, Request, Response } from "express";
import sessionModel from "../modules/auth/models/session.schema.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../configs/app.config.js";
import bcrypt from "bcryptjs";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";

type RequestWithUser = Request & {
	userID?: string;
	sessionId?: string;
};

/**
 * Verify access token from cookies
 * Lightweight check - only validates JWT signature and expiry
 */
export const accessTokenHandler = asyncErrorHandler(
	async (req: RequestWithUser, res: Response, next: NextFunction) => {
		const accessToken = req.cookies.acToken;

		if (!accessToken) {
			return res.status(401).json({
				success: false,
				error: "Unauthorized",
				message: "Access token not found",
			});
		}

		// Verify JWT signature and expiry (throws error if invalid)
		const decoded = jwt.verify(accessToken, config.ACCESS_TOKEN_JWT_SECRET) as JwtPayload;

		// Attach userID to request for downstream use
		req.userID = decoded.id;
		req.sessionId = decoded.sessionId; // Optional: if you include sessionId in JWT

		next();
	},
);

/**
 * Verify refresh token and check session validity
 * Heavy check - validates JWT + database session + token family
 */
export const refreshTokenHandler = asyncErrorHandler(
	async (req: RequestWithUser, res: Response, next: NextFunction) => {
		const refreshToken = req.cookies.rfToken;

		if (!refreshToken) {
			return res.status(401).json({
				success: false,
				error: "Unauthorized",
				message: "Refresh token not found",
			});
		}

		// 1. Verify JWT signature and expiry
		const decoded = jwt.verify(refreshToken, config.REFRESH_TOKEN_JWT_SECRET) as JwtPayload;

		// 2. Find active session in database
		const session = await sessionModel
			.findOne({
				userId: decoded.id,
				status: "active",
				isRevoked: false,
			})
			.select("+refreshTokenHash"); // Include select: false field

		if (!session) {
			return res.status(401).json({
				success: false,
				error: "SessionNotFound",
				message: "Session not found or revoked",
			});
		}

		// 3. Verify refresh token hash
		const isTokenValid = await bcrypt.compare(
			refreshToken,
			session.refreshTokenHash,
		);

		if (!isTokenValid) {
			return res.status(401).json({
				success: false,
				error: "InvalidToken",
				message: "Invalid refresh token",
			});
		}

		// 4. Check token family (theft detection)
		if (decoded.tokenFamily && decoded.tokenFamily !== session.tokenFamily) {
			// Token family mismatch = token theft detected
			console.warn(
				`⚠️ Token theft detected for user ${decoded.id}. Revoking all sessions.`,
			);

			// Revoke all user sessions ("lose 1, lose all")
			await sessionModel.revokeAllUserSessions(
				decoded.id,
				"Token theft detected",
			);

			return res.status(401).json({
				success: false,
				error: "TokenTheftDetected",
				message: "Security alert: All sessions revoked. Please login again.",
			});
		}

		// 5. Check session expiry
		if (session.refreshTokenExpiresAt < new Date()) {
			await session.revoke("Token expired");

			return res.status(401).json({
				success: false,
				error: "TokenExpired",
				message: "Refresh token expired",
			});
		}

		// 6. Update last activity
		await session.updateActivity();

		// Attach to request
		req.userID = decoded.id;
		req.sessionId = session._id.toString();

		next();
	},
);

/**
 * Strict middleware that checks both access token AND session validity
 * Use for sensitive operations (delete account, change password, etc.)
 */
export const strictAuthHandler = asyncErrorHandler(
	async (req: RequestWithUser, res: Response, next: NextFunction) => {
		const accessToken = req.cookies.acToken;

		if (!accessToken) {
			return res.status(401).json({
				success: false,
				error: "Unauthorized",
				message: "Access token required",
			});
		}

		const decoded = jwt.verify(accessToken, config.ACCESS_TOKEN_JWT_SECRET) as JwtPayload;

		// Verify session still exists and is active
		const session = await sessionModel.findOne({
			userId: decoded.id,
			status: "active",
			isRevoked: false,
		});

		if (!session) {
			return res.status(401).json({
				success: false,
				error: "SessionInvalid",
				message: "Session expired or revoked",
			});
		}

		req.userID = decoded.id;
		req.sessionId = session._id.toString();

		next();
	},
);
