import { NextFunction, Request, Response } from "express";
import { JwtPayload } from "jsonwebtoken";
import jwt from "jsonwebtoken";
import { config } from "../../../configs/app.config.js";
import {
	apiKeyCreationSchema,
	updateApiIPWhiteListSchema,
	updateApiKeySchema,
	updateApiNameSchema,
	updateApiScopesSchema,
} from "../../../libs/zod/apikey.zodschema.js";
import * as z from "zod";
import crypto from "crypto";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import mongoose from "mongoose";
import { Model } from "mongoose";
import {
	ApiKeyDocument,
	ApiKeyStaticMethods,
} from "../../../types/mongo_models/apikeys.type.js";
import {
	UserDocument,
	UserStaticMethods,
} from "../../../types/mongo_models/user.type.js";

export const createApiKeyController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
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
		const user: UserDocument | null = await userModel.findById(userId);

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

		const apiKey: ApiKeyDocument = await apiKeyModel.create({
			userId,
			name,
			description,
			keyHash: apiKeyValue,
			keyPrefix: apiKeyValue.slice(0, 8),
			keyHint: apiKeyValue.slice(-4),
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

export const listApiKeysController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
) => {
	try {
		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const userId = decoded.id;
		const apiKeys = await apiKeyModel
			.find({ userId })
			.select("-keyHash")
			.sort({ createdAt: -1 })
			.lean();

		return res
			.status(200)
			.json(standardResponse(true, "API keys fetched successfully", apiKeys));
	} catch (error) {
		next(error);
	}
};

export const revokeApiKeyController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
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

		const userId = decoded.id;
		const apiKey: ApiKeyDocument | null = await apiKeyModel.findOne({
			_id: keyId,
			userId,
		});

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

export const deleteApiKeyController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
) => {
	try {
		const { keyId } = req.params;
		if (!keyId || !(typeof keyId === "string")) {
			return res.status(400).json(standardResponse(false, "keyId is required"));
		}

		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const userId = decoded.id;

		const apiKey = await apiKeyModel
			.findOneAndDelete({ _id: keyId, userId })
			.lean();

		if (!apiKey) {
			return res.status(404).json(standardResponse(false, "API key not found"));
		}
		return res
			.status(200)
			.json(standardResponse(true, "API key deleted successfully", apiKey));
	} catch (error) {
		next(error);
	}
};

export const updateApiKeyController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
) => {
	try {
		const { keyId, keyUpdatesDetails }: z.infer<typeof updateApiKeySchema> =
			req.body;
		if (!keyId || !keyUpdatesDetails) {
			return res
				.status(400)
				.json(
					standardResponse(false, "keyId and keyUpdatesDetails are required"),
				);
		}
		if (!mongoose.Types.ObjectId.isValid(keyId)) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid keyId format"));
		}

		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}
		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const userId = decoded.id;

		const apiKey = await apiKeyModel
			.findOneAndUpdate(
				{ _id: keyId, userId },
				{ $set: keyUpdatesDetails },
				{ new: true, runValidators: true },
			)
			.lean();

		if (!apiKey) {
			return res.status(404).json(standardResponse(false, "API key not found"));
		}

		return res
			.status(200)
			.json(standardResponse(true, "API key updated successfully", apiKey));
	} catch (error) {
		next(error);
	}
};

export const updateApiKeyNameController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
) => {
	try {
		const { keyId, newName }: z.infer<typeof updateApiNameSchema> = req.body;
		if (!keyId || !newName) {
			return res
				.status(400)
				.json(standardResponse(false, "keyId and newName are required"));
		}
		if (!mongoose.Types.ObjectId.isValid(keyId)) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid keyId format"));
		}

		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const apikey = await apiKeyModel
			.findOneAndUpdate(
				{ _id: keyId, userId: decoded.id },
				{ $set: { name: newName } },
				{ new: true, runValidators: true },
			)
			.lean();
		if (!apikey) {
			return res.status(404).json(standardResponse(false, "API key not found"));
		}
		return res.status(200).json(
			standardResponse(true, "API key name updated successfully", {
				updateStatus: "success",
				apikey,
			}),
		);
	} catch (error) {
		next(error);
	}
};

export const updateApiKeyScopesController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
) => {
	try {
		const { keyId, newScopes }: z.infer<typeof updateApiScopesSchema> =
			req.body;
		if (!keyId || !newScopes) {
			return res
				.status(400)
				.json(standardResponse(false, "keyId and newScopes are required"));
		}
		if (!mongoose.Types.ObjectId.isValid(keyId)) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid keyId format"));
		}

		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const apikey = await apiKeyModel
			.findOneAndUpdate(
				{ _id: keyId, userId: decoded.id },
				{ $set: { scopes: newScopes } },
				{ new: true, runValidators: true },
			)
			.lean();
		if (!apikey) {
			return res.status(404).json(standardResponse(false, "API key not found"));
		}
		return res.status(200).json(
			standardResponse(true, "API key scopes updated successfully", {
				updateStatus: "success",
				apikey,
			}),
		);
	} catch (error) {
		next(error);
	}
};

export const updateApiKeyIPWhiteListController = async (
	req: Request,
	res: Response,
	next: NextFunction,
	userModel: Model<UserDocument, UserStaticMethods>,
	apiKeyModel: Model<ApiKeyDocument, ApiKeyStaticMethods>,
) => {
	try {
		const { keyId, newIPs }: z.infer<typeof updateApiIPWhiteListSchema> =
			req.body;
		if (!keyId || !newIPs) {
			return res
				.status(400)
				.json(standardResponse(false, "keyId and newIPs are required"));
		}
		if (!mongoose.Types.ObjectId.isValid(keyId)) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid keyId format"));
		}

		if (!req.cookies.acToken) {
			return res.status(401).json(standardResponse(false, "Unauthorized"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;
		const apikey = await apiKeyModel
			.findOneAndUpdate(
				{ _id: keyId, userId: decoded.id },
				{ $set: { allowedIPs: newIPs } },
				{ new: true, runValidators: true },
			)
			.lean();
		if (!apikey) {
			return res.status(404).json(standardResponse(false, "API key not found"));
		}
		return res.status(200).json(
			standardResponse(true, "API key IP whitelist updated successfully", {
				updateStatus: "success",
				apikey,
			}),
		);
	} catch (error) {
		next(error);
	}
};
