import type { NextFunction, Request, Response } from "express";
import { standardResponse } from "../utils/apiResponse.utils.js";
import {
	ApiKeyDocument,
	ApiKeyStaticMethods,
} from "../types/mongoModels/apikeys.type.js";
type RequestWithOwnerId = Request & { apiOwnerId?: string; apiKeyId?: string; apiKeyDoc?: ApiKeyDocument };

export async function resolveScopes(
	req: RequestWithOwnerId,
	res: Response,
	next: NextFunction,
	apiKeyModel: ApiKeyStaticMethods,
) {
	try {
		if (!req.apiKeyDoc || !req.apiOwnerId) {
			return res.status(401).json(
				standardResponse(false, "Unauthorized: API key is missing or invalid"),
			);
		}

		if (!req.apiKeyDoc.hasScope(req.method)) {
			return res.status(403).json(
				standardResponse(false, "Forbidden: Insufficient permissions for this endpoint"),
			);
		}
		next();
	} catch (err: any) {
		next(err);
	}
}
