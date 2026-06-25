import type { NextFunction, Request, Response } from "express";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../configs/app.config.js";
import bcrypt from "bcryptjs";
import { tokenMiddlewareResponse } from "../utils/apiResponse.utils.js";
import { UserDocument, UserStaticMethods } from "../types/mongo_models/user.type.js";
import { SessionDocument, SessionStaticMethods } from "../types/mongo_models/session.type.js";

type RequestWithUser = Request & {
	userID?: string;
	sessionId?: string;
};

/**
 * Verify access token from cookies
 * Lightweight check - only validates JWT signature and expiry
 */
export const accessTokenHandlerFunction = async (
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	sessionModel: SessionStaticMethods,
) => {
	const accessToken = req.cookies.acToken;
	if (!accessToken) {
		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Access token not found",
					"Unauthorized",
					true,
				),
			);
	}

	// Verify JWT signature and expiry (throws error if invalid)
	const decoded = jwt.verify(
		accessToken,
		config.ACCESS_TOKEN_JWT_SECRET,
	) as JwtPayload;
	if (!decoded) {
		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Invalid access token",
					"InvalidToken",
					true,
				),
			);
	}

	req.userID = decoded.id;
	req.sessionId = decoded.sessionId;
	next();
};

/**
 * Verify refresh token and check session validity
 * Heavy check - validates JWT + database session + token family
 */
export const refreshTokenHandlerFunction = async (
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	sessionModel: SessionStaticMethods,
) => {
	const refreshToken = req.cookies.rfToken;
	if (!refreshToken) {
		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Refresh token not found",
					"Unauthorized",
					true,
				),
			);
	}

	// 1. Verify JWT signature and expiry
	const decoded = jwt.verify(
		refreshToken,
		config.REFRESH_TOKEN_JWT_SECRET,
	) as JwtPayload;

	// 2. Find active session in database
	const session = await sessionModel
		.findOne({
			userId: decoded.id,
			status: "active",
			isRevoked: false,
		})
		.select("+refreshTokenHash"); // Include select: false field

	if (!session) {
		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Session not found or revoked",
					"SessionNotFound",
					true,
				),
			);
	}

	// 3. Verify refresh token hash
	const isTokenValid = await bcrypt.compare(
		refreshToken,
		session.refreshTokenHash,
	);

	if (!isTokenValid) {
		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Invalid refresh token",
					"InvalidToken",
					true,
				),
			);
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

		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Security alert: All sessions revoked. Please login again.",
					"TokenTheftDetected",
					true,
				),
			);
	}

	// 5. Check session expiry
	if (session.refreshTokenExpiresAt < new Date()) {
		await session.revoke("Token expired");

		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Refresh token expired",
					"TokenExpired",
					true,
				),
			);
	}

	// 6. Update last activity
	await session.updateActivity();

	// Attach to request
	req.userID = decoded.id;
	req.sessionId = session._id.toString();

	next();
};

/**
 * Strict middleware that checks both access token AND session validity
 * Use for sensitive operations (delete account, change password, etc.)
 */
export const strictAuthHandlerFunction = async (
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	sessionModel: SessionStaticMethods,
) => {
	const accessToken = req.cookies.acToken;

	if (!accessToken) {
		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Access token required",
					"Unauthorized",
					true,
				),
			);
	}

	const decoded = jwt.verify(
		accessToken,
		config.ACCESS_TOKEN_JWT_SECRET,
	) as JwtPayload;

	// Verify session still exists and is active
	const session: SessionDocument | null = await sessionModel.findOne({
		userId: decoded.id,
		status: "active",
		isRevoked: false,
	});

	if (!session) {
		return res
			.status(401)
			.json(
				tokenMiddlewareResponse(
					false,
					"Session expired or revoked",
					"SessionInvalid",
					true,
				),
			);
	}

	req.userID = decoded.id;
	req.sessionId = session._id.toString();

	next();
};
