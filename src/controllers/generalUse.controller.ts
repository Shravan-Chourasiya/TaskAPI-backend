import type { NextFunction, Request, Response } from "express";
import { config } from "../configs/app.config.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import userModel from "../modules/auth/models/user.schema.js";
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
import { usernameSchema } from "../libs/zod/auth.zodschema.js";

export const isUserController = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		// This endpoint is protected by accessTokenHandler, so if we reach here, the user is verified
		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		if (!decoded) {
			return res
				.status(401)
				.json(isUserResponse(false, "Invalid token", false, null));
		}
		const user = await userModel.findById(decoded.id);
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
				role: user.roles,
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
				role: user.roles,
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

export const healthCheckController = (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		res.status(200).json({ status: "OK", message: "Health check passed" });
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
) => {
	try {
		const { username }= req.query;
		console.log(username, typeof username);
		if (!username || typeof username !== "string") {
			return res
				.status(400)
				.json(
					standardResponse(false, "Username is required and must be a string"),
				);
		}

		const existingUser = await userModel.findOne({ username });
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
