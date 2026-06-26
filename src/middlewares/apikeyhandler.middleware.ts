import { Request, Response, NextFunction } from "express";
import bcrypt from "bcryptjs";
import { standardResponse } from "../utils/apiResponse.utils.js";
import {
	ApiKeyDocument,
	ApiKeyStaticMethods,
} from "../types/mongoModels/apikeys.type.js";

type RequestWithApiOwner = Request & {
	apiOwnerId?: string;
};

export const apikeyHandlerFunction = async (
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	apiKeyModel: ApiKeyStaticMethods,
) => {
	const apiKey = req.headers["x-api-key"] as string | undefined;

	if (!apiKey || typeof apiKey !== "string") {
		return res
			.status(401)
			.json(standardResponse(false, "Unauthorized: API key is missing"));
	}

	// Extract prefix (first 8 chars) to narrow DB lookup before bcrypt compare
	const keyPrefix = apiKey.substring(0, 8);

	const apiKeyDoc: ApiKeyDocument | null = await apiKeyModel
		.findOne({
			keyPrefix,
			keyStatus: "active",
			isRevoked: false,
			isBlacklisted: false,
		})
		.select("+keyHash");

	if (!apiKeyDoc) {
		return res
			.status(401)
			.json(
				standardResponse(false, "Unauthorized: Invalid or revoked API key"),
			);
	}

	// Check expiry
	if (apiKeyDoc.expiresAt && new Date() > apiKeyDoc.expiresAt) {
		return res
			.status(401)
			.json(standardResponse(false, "Unauthorized: API key has expired"));
	}

	// Verify full key against stored hash
	const isValid = await bcrypt.compare(apiKey, apiKeyDoc.keyHash);
	if (!isValid) {
		return res
			.status(401)
			.json(standardResponse(false, "Unauthorized: Invalid API key"));
	}

	// Attach owner's userId to request for downstream controllers
	req.apiOwnerId = apiKeyDoc.userId.toString();

	next();
};
