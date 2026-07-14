import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { ApiKeyStaticMethods } from "../../../types/mongoModels/apikeys.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser, isAdmin } from "../utils/siteAdminController.utils.js";

type RequestWithUser = Request & { userID?: string };

type Deps = {
	userModel: UserStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
};

export async function getUserApiKeys(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { userId } = req.params;
		if (!userId) {
			return res.status(400).json(standardResponse(false, "Missing userId", null));
		}
		const keys = await apiKeyModel.find({ userId }).lean();
		if (!keys || keys.length === 0) {
			return res.status(404).json(standardResponse(false, "No API keys found", null));
		}

		return res.status(200).json(standardResponse(true, "API keys fetched successfully", keys));
	} catch (err) {
		next(err);
	}
}

export async function revokeApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		if (!isAdmin(admin)) {
			return res.status(403).json(standardResponse(false, "Only admins can revoke API keys", null));
		}

		const { keyId } = req.params;
		const { reason }: { reason?: string } = req.body;

		const key = await apiKeyModel.findById(keyId);
		if (!key) {
			return res.status(404).json(standardResponse(false, "API key not found", null));
		}

		await key.revoke(reason);
		return res.status(200).json(standardResponse(true, "API key revoked successfully", null));
	} catch (err) {
		next(err);
	}
}

export async function blacklistApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		if (!isAdmin(admin)) {
			return res.status(403).json(standardResponse(false, "Only admins can blacklist API keys", null));
		}

		const { keyId } = req.params;
		const { reason }: { reason?: string } = req.body;

		const key = await apiKeyModel.findById(keyId);
		if (!key) {
			return res.status(404).json(standardResponse(false, "API key not found", null));
		}

		await key.blacklist(reason);
		return res.status(200).json(standardResponse(true, "API key blacklisted successfully", null));
	} catch (err) {
		next(err);
	}
}
