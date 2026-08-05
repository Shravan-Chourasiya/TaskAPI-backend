import type { NextFunction, Request, Response } from "express";
import { config } from "../configs/app.config.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import mongoose from "mongoose";
import { redisClient } from "../configs/redis.init.js";
import { contactUsSchema } from "../libs/zod/general.zodschema.js";
import * as z from "zod";
import {
	sendContactUsEmail,
	sendVerificationEmail,
} from "../services/nodemailer.service.js";
import { getContactUsHTML } from "../utils/nodemailer.utils.js";
import {
	isUserResponse,
	standardResponse,
} from "../utils/apiResponse.utils.js";
import { Model } from "mongoose";
import {
	UserDocument,
	UserStaticMethods,
} from "../types/mongoModels/user.type.js";

export const isUserController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
) => {
	try {
		// This endpoint is protected by accessTokenHandler, so if we reach here, the user is verified
		// amazonq-ignore-next-line
		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		if (!decoded) {
			return res
				.status(401)
				.json(isUserResponse(false, "Invalid token", false, null));
		}
		const user: UserDocument | null = await userModel.findById(decoded.id);
		if (!user) {
			return res
				.status(404)
				.json(isUserResponse(false, "User not found", false, null));
		}
		if (user.status !== "active") {
			return res
				.status(403)
				.json(
					isUserResponse(
						false,
						"User is not verified or Account is Inactive/Suspended",
						false,
						null,
					),
				);
		}
		if (user.isPhoneVerified) {
			const userObj = {
				username: user.username,
				email: user.email,
				status: user.status,
				role: user.role,
				profile: user.profile,
				phone: user.phone,
			};
			return res
				.status(200)
				.json(isUserResponse(true, "User is verified", true, userObj));
		} else {
			const userObj = {
				username: user.username,
				email: user.email,
				status: user.status,
				role: user.role,
				profile: user.profile,
			};
			return res
				.status(200)
				.json(isUserResponse(true, "User is verified", true, userObj));
		}
	} catch (error) {
		next(error);
	}
};

export const healthCheckController = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const results = await Promise.allSettled([
			// Mongo — readyState: 1=connected
			Promise.resolve(mongoose.connection.readyState),
			// Redis — lightweight round-trip with a short timeout
			redisClient.ping().then(
				(v) => v,
				(err) => {
					throw err;
				},
			),
		]);

		const mongoResult = results[0];
		const redisResult = results[1];

		const dbUp =
			mongoResult.status === "fulfilled" && mongoResult.value === 1;
		const redisUp = redisResult.status === "fulfilled";

		const checks = {
			db: { status: dbUp ? "up" : "down" },
			redis: { status: redisUp ? "up" : "down" },
		};

		const statusCode = dbUp && redisUp ? 200 : 503;

		res.status(statusCode).json({
			status: statusCode === 200 ? "OK" : "DEGRADED",
			message: statusCode === 200 ? "Health check passed" : "Dependency check failed",
			checks,
		});
	} catch (error) {
		next(error);
	}
};

export const contactUsEmailController = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const { name, email, message }: z.infer<typeof contactUsSchema> = req.body;

		const html = getContactUsHTML(name, email, message);

		await sendContactUsEmail(email, config.GMAIL_USER_EMAIL, name, html);

		res
			.status(200)
			.json(standardResponse(true, "Your message has been sent successfully"));
	} catch (error) {
		next(error);
	}
};

export const checkUsernameController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
) => {
	try {
		// amazonq-ignore-next-line
		const { username } = req.query;
		if (!username || typeof username !== "string") {
			return res
				.status(400)
				.json(
					standardResponse(false, "Username is required and must be a string"),
				);
		}

		const existingUser: UserDocument | null = await userModel.findOne({
			username,
		});
		if (existingUser) {
			return res
				.status(409)
				.json(standardResponse(false, "Username is already taken"));
		}

		return res
			.status(200)
			.json(standardResponse(true, "Username is available"));
	} catch (error) {
		next(error);
	}
};
