import type { NextFunction, Request, Response } from "express";
import { sessionModel } from "../models/session.model.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "../configs/configs.js";

type RequestWithUser = Request & {
	userID?: string;
};

export async function accessTokenHandler(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
) {
	if (!req.cookies.acToken || req.cookies.acToken === "") {
		return res.status(401).json({
			message: "Unauthorized | Access Token Not found!.",
		});
	} else {
		const decoded = jwt.verify(
			req.cookies.acToken,
			config.JWT_SECRET_2,
		) as JwtPayload;
		req.userID = decoded.id;
		next();
	}
}

export async function refreshTokenHandler(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
) {
	if (!req.cookies.rfToken || req.cookies.rfToken === "") {
		return res.status(400).json({
			message: "Invalid Request | Refresh Token Not found!.",
		});
	}
	const decoded = jwt.verify(
		req.cookies.rfToken,
		config.JWT_SECRET,
	) as JwtPayload;
	const rfTokenRecord = await sessionModel.findOne({
		userId: decoded.id,
		refreshToken: req.cookies.rfToken,
	});
	if (!rfTokenRecord) {
		return res.status(401).json({
			message: "Unauthorized | Invalid Refresh Token!.",
		});
	}
	if (rfTokenRecord.expiresAt < new Date()) {
		return res.status(401).json({
			message: "Unauthorized | Refresh Token Expired!.",
		});
	}
	next();
}
