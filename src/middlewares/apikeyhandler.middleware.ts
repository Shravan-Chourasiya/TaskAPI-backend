import { Request, Response, NextFunction } from "express";
import bcrypt from "bcryptjs";
import { standardResponse } from "../utils/apiResponse.utils.js";
import {
	ApiKeyDocument,
	ApiKeyStaticMethods,
} from "../types/mongoModels/apikeys.type.js";

type RequestWithApiOwner = Request & {
	apiOwnerId?: string;
	apiKeyId?:   string;
	apiKeyDoc?:  ApiKeyDocument;
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

	// Attach owner's userId, key id, and the full validated doc for downstream
	// resolvers (IP, scope) so they don't need to re-fetch.
	req.apiOwnerId = apiKeyDoc.userId.toString();
	req.apiKeyId   = String((apiKeyDoc._id as { toString(): string }).toString());
	req.apiKeyDoc  = apiKeyDoc;

	next();
};
