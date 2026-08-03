import type { NextFunction, Request, Response } from "express";
import { standardResponse } from "../utils/apiResponse.utils.js";
import {
	ApiKeyDocument,
	ApiKeyStaticMethods,
} from "../types/mongoModels/apikeys.type.js";
type RequestWithOwnerId = Request & { apiOwnerId?: string; apiKeyId?: string; apiKeyDoc?: ApiKeyDocument };

export async function resolveIP(
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

		if (!req.ip) {
			return res.status(400).json(
				standardResponse(false, "Bad Request: Unable to resolve IP address"),
			);
		}
		if (req.ip === "::1") return next();

		// Normalize IPv4-mapped IPv6 (e.g. ::ffff:1.2.3.4 -> 1.2.3.4)
		const clientIp = req.ip.startsWith("::ffff:") ? req.ip.slice(7) : req.ip;

		if (req.apiKeyDoc.isIPAllowed(clientIp)) {
			return next();
		}
		return res.status(403).json(
			standardResponse(false, "Forbidden: Your IP address is not allowed to use this API key"),
		);
	} catch (err: any) {
		next(err);
	}
}
