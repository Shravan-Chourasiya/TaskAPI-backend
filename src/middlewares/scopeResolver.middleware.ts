import type { NextFunction, Request, Response } from "express";
import { standardResponse } from "../utils/apiResponse.utils.js";
import {
	ApiKeyDocument,
	ApiKeyStaticMethods,
} from "../types/mongoModels/apikeys.type.js";
type RequestWithOwnerId = Request & { apiOwnerId?: string; apiKeyId?: string };

export async function resolveScopes(
	req: RequestWithOwnerId,
	res: Response,
	next: NextFunction,
	apiKeyModel: ApiKeyStaticMethods,
) {
	try {
		if (
			!req.headers["x-api-key"] ||
			typeof req.headers["x-api-key"] !== "string" ||
			req.headers["x-api-key"] === "" ||
			!req.apiKeyId ||
			!req.apiOwnerId
		) {
			return res
				.status(401)
				.json(
					standardResponse(
						false,
						"Unauthorized: API key is missing or invalid",
					),
				);
		}

		const apiKeyDoc: ApiKeyDocument | null = await apiKeyModel.findOne({
			_id: req.apiKeyId.toString(),
			userId: req.apiOwnerId,
		});
		if (!apiKeyDoc || apiKeyDoc === null) {
			return res
				.status(401)
				.json(
					standardResponse(false, "Unauthorized: API key not found or invalid"),
				);
		}
		const isScopeAllowed = apiKeyDoc.hasScope(req.method);
		if (!isScopeAllowed) {
			return res
				.status(403)
				.json(
					standardResponse(
						false,
						"Forbidden: Insufficient permissions for this endpoint",
					),
				);
		}
		next();
	} catch (err: any) {
		next(err);
	}
}
