import { NextFunction, Request, Response } from "express";
import { JwtPayload } from "jsonwebtoken";
import jwt from "jsonwebtoken";
import { config } from "../../../configs/app.config.js";
import { apiKeyCreationSchema } from "../../../libs/zod/apikey.zodschema.js";
import userModel from "../models/user.schema.js";
import * as z from "zod";
import { apiKeyModel } from "../models/apikey.schema.js";
import crypto from "crypto";
import { standardResponse } from "../../../utils/apiResponse.utils.js";

export const createApiKey = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const {
			name,
			description,
			env,
			scopes,
			allowedIPs,
		}: z.infer<typeof apiKeyCreationSchema> = req.body;
		if (
			!name ||
			!scopes ||
			!allowedIPs ||
			!env ||
			!scopes ||
			!req.cookies.acToken
		) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required fields"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const userId = decoded.id;
		console.log("#####1:Decoded JWT payload:", decoded, userId);
		const user = await userModel.findById(userId);

		if (!user) {
			return res.status(404).json(standardResponse(false, "User not found"));
		}
		if (
			(user.subscriptionExpiryDate &&
				new Date() > user.subscriptionExpiryDate) ||
			!user.subscriptionType
		) {
			return res
				.status(403)
				.json(
					standardResponse(
						false,
						"User subscription has expired, cannot create new API keys",
					),
				);
		}
		console.log(
			`#####2: User subscription type: ${user.subscriptionType}, API key count: ${user.apiKeyCount} #####`,
		);
		if (user.subscriptionType === "Free" && user.apiKeyCount >= 5) {
			return res
				.status(400)
				.json(standardResponse(false, "Free users can only create 5 API keys"));
		}
		if (user.subscriptionType === "Basic" && user.apiKeyCount >= 10) {
			return res
				.status(400)
				.json(
					standardResponse(false, "Basic users can only create 10 API keys"),
				);
		}
		if (user.subscriptionType === "Pro" && user.apiKeyCount >= 25) {
			return res
				.status(400)
				.json(standardResponse(false, "Pro users can only create 25 API keys"));
		}

		if (
			user.isBlackListed ||
			user.isDeleted ||
			!user.isVerified ||
			user.status !== "active"
		) {
			return res
				.status(403)
				.json(
					standardResponse(false, "User is forbidden from creating API keys"),
				);
		}
		const apiKeyValue = `tk_${env}_${crypto.randomBytes(16).toString("hex")}`;

		console.log(
			"#####3: User passed all checks, proceeding to create API key with value:",
			apiKeyValue,
		);

		const apiKey = await apiKeyModel.create({
			userId,
			name,
			description,
			keyHash: apiKeyValue,
			keyPrefix: apiKeyValue.slice(0, 8),
			keyHint:apiKeyValue.slice(-4),
			subscriptionType: user.subscriptionType,
			scopes,
			keyStatus: "active",
			allowedIPs,
			environment: env,
			expiresAt: user.subscriptionExpiryDate,
		});

		user.apiKeyCount = (user.apiKeyCount || 0) + 1;
		await user.save();
		console.log(
			"#####4: API key created successfully with value:",
			apiKeyValue,
		);
		return res.status(201).json(
			standardResponse(true, "API key created successfully", {
				apiKey: apiKeyValue,
				apiKeyId: apiKey._id,
				apiKeyPrefix: apiKey.keyPrefix,
				apiKeyCreatorId: apiKey.userId,
			}),
		);
	} catch (error) {
		next(error);
	}
};

export const listApiKeys = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const userId = decoded.userId;
		const apiKeys = await apiKeyModel
			.find({ userId })
			.select("-keyHash")
			.sort({ createdAt: -1 });

		return res
			.status(200)
			.json(standardResponse(true, "API keys fetched successfully", apiKeys));
	} catch (error) {
		next(error);
	}
};

export const revokeApiKey = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const { keyId } = req.params;
		const { reason } = req.body;

		if (reason && typeof reason !== "string") {
			return res
				.status(400)
				.json(standardResponse(false, "Reason must be a string"));
		}

		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const userId = decoded.userId;
		const apiKey = await apiKeyModel.findOne({ _id: keyId, userId });

		if (!apiKey) {
			return res.status(404).json(standardResponse(false, "API key not found"));
		}

		await apiKey.revoke(reason);

		return res
			.status(200)
			.json(standardResponse(true, "API key revoked successfully"));
	} catch (error) {
		next(error);
	}
};
