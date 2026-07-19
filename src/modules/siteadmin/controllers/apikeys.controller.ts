import crypto from "crypto";
import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { ApiKeyStaticMethods } from "../../../types/mongoModels/apikeys.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import {
	resolveAdminUser,
	isAdmin,
} from "../utils/siteAdminController.utils.js";

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
			return res
				.status(400)
				.json(standardResponse(false, "Missing userId", null));
		}
		const keys = await apiKeyModel.find({ userId }).lean();
		if (!keys || keys.length === 0) {
			return res
				.status(404)
				.json(standardResponse(false, "No API keys found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "API keys fetched successfully", keys));
	} catch (err) {
		next(err);
	}
}

// suspends an API key, preventing its use without deleting it
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
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can revoke API keys", null));
		}

		const { keyId } = req.params;
		const { reason }: { reason?: string } = req.body;

		const key = await apiKeyModel.findById(keyId);
		if (!key) {
			return res
				.status(404)
				.json(standardResponse(false, "API key not found", null));
		}

		await key.revoke(reason);
		return res
			.status(200)
			.json(standardResponse(true, "API key revoked successfully", null));
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
			return res
				.status(403)
				.json(
					standardResponse(false, "Only admins can blacklist API keys", null),
				);
		}

		const { keyId } = req.params;
		const { reason }: { reason?: string } = req.body;

		const key = await apiKeyModel.findById(keyId);
		if (!key) {
			return res
				.status(404)
				.json(standardResponse(false, "API key not found", null));
		}

		await key.blacklist(reason);
		return res
			.status(200)
			.json(standardResponse(true, "API key blacklisted successfully", null));
	} catch (err) {
		next(err);
	}
}

// ================================================ NEWLY ADDED =============================================
export async function createUserApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can create API keys", null));
		}

		const { userId } = req.params;
		const { name, description, env, scopes, allowedIPs } = req.body;

		if(typeof userId !== "string") {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid userId", null));
		}

		if (!name || !env || !scopes) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required fields", null));
		}

		const user = await userModel.findById(userId);
		if (!user) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		const apiKeyValue = `tk_${env}_${crypto.randomBytes(16).toString("hex")}`;
		const apiKey = await apiKeyModel.create({
			userId: String(userId),
			name,
			...(description !== undefined && { description }),
			keyHash: apiKeyValue,
			keyPrefix: apiKeyValue.slice(0, 8),
			keyHint: apiKeyValue.slice(-4),
			subscriptionType: user.subscriptionType,
			scopes,
			keyStatus: "active",
			allowedIPs: allowedIPs ?? ["0.0.0.0"],
			environment: env,
			expiresAt: user.subscriptionExpiryDate,
		});

		await userModel.findByIdAndUpdate(userId, { $inc: { apiKeyCount: 1 } });

		return res.status(201).json(
			standardResponse(true, "API key created successfully", {
				apiKey: apiKeyValue,
				apiKeyId: apiKey._id,
				apiKeyPrefix: apiKey.keyPrefix,
			}),
		);
	} catch (err: any) {
		next(err);
	}
}

export async function deleteApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can delete API keys", null));
		}

		const { keyId } = req.params;
		const key = await apiKeyModel.findByIdAndDelete(keyId).lean();
		if (!key) {
			return res
				.status(404)
				.json(standardResponse(false, "API key not found", null));
		}

		await userModel.findByIdAndUpdate(key.userId, { $inc: { apiKeyCount: -1 } });
		return res
			.status(200)
			.json(standardResponse(true, "API key deleted successfully", null));
	} catch (err: any) {
		next(err);
	}
}

export async function restoreApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(false, "Only admins can restore API keys", null),
				);
		}

		const { keyId } = req.params;
		const key = await apiKeyModel.findByIdAndUpdate(
			keyId,
			{
				$set: { keyStatus: "active", isRevoked: false, isBlacklisted: false },
				$unset: { revokedAt: "", revokedReason: "", blacklistedAt: "", blacklistedReason: "" },
			},
			{ new: true },
		);
		if (!key) {
			return res
				.status(404)
				.json(standardResponse(false, "API key not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "API key restored successfully", null));
	} catch (err: any) {
		next(err);
	}
}

export async function modifyApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can modify API keys", null));
		}

		const { keyId } = req.params;
		const { name, description, scopes, allowedIPs, keyStatus } = req.body;

		const updates: Record<string, unknown> = {};
		if (name !== undefined) updates.name = name;
		if (description !== undefined) updates.description = description;
		if (scopes !== undefined) updates.scopes = scopes;
		if (allowedIPs !== undefined) updates.allowedIPs = allowedIPs;
		if (keyStatus !== undefined) updates.keyStatus = keyStatus;

		if (Object.keys(updates).length === 0) {
			return res
				.status(400)
				.json(standardResponse(false, "No fields provided for update", null));
		}

		const key = await apiKeyModel.findByIdAndUpdate(
			keyId,
			{ $set: updates },
			{ new: true, runValidators: true },
		);
		if (!key) {
			return res
				.status(404)
				.json(standardResponse(false, "API key not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "API key updated successfully", key));
	} catch (err: any) {
		next(err);
	}
}

export async function rotateApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can rotate API keys", null));
		}

		const { keyId } = req.params;
		const key = await apiKeyModel.findById(keyId);
		if (!key) {
			return res
				.status(404)
				.json(standardResponse(false, "API key not found", null));
		}

		const newKeyValue = `tk_${key.environment}_${crypto.randomBytes(16).toString("hex")}`;
		key.keyHash = newKeyValue;
		key.keyPrefix = newKeyValue.slice(0, 8);
		key.keyHint = newKeyValue.slice(-4);
		key.keyStatus = "active";
		key.isRevoked = false;
		key.isBlacklisted = false;
		await key.save();

		return res.status(200).json(
			standardResponse(true, "API key rotated successfully", {
				apiKey: newKeyValue,
				apiKeyPrefix: key.keyPrefix,
			}),
		);
	} catch (err: any) {
		next(err);
	}
}

export async function whitelistApiKey(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, apiKeyModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(
					standardResponse(false, "Only admins can whitelist API keys", null),
				);
		}

		const { keyId } = req.params;
		const key = await apiKeyModel.findByIdAndUpdate(
			keyId,
			{
				$set: { keyStatus: "active", isBlacklisted: false },
				$unset: { blacklistedAt: "", blacklistedReason: "" },
			},
			{ new: true },
		);
		if (!key) {
			return res
				.status(404)
				.json(standardResponse(false, "API key not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "API key whitelisted successfully", null));
	} catch (err: any) {
		next(err);
	}
}
