import type { Request, Response } from "express";
import { standardResponse } from "../../../utils/apiResponse.utils.js";

type RequestWithApiOwner = Request & { apiOwnerId?: string };

export function resolveClientId(req: RequestWithApiOwner, res: Response): string | null {
	const clientId = req.apiOwnerId;
	if (!clientId) {
		res.status(401).json(standardResponse(false, "Unauthorized: missing API owner identity", null));
		return null;
	}
	return clientId;
}
