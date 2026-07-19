import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { RawEventModel } from "../../metrics/types/rawEvent.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser, isAdmin } from "../utils/siteAdminController.utils.js";

type RequestWithUser = Request & { userID?: string };

type Deps = {
	userModel: UserStaticMethods;
	rawEventModel: RawEventModel;
};

export async function getAdminAuditLogs(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can view audit logs", null));
		}

		const { from, to, limit = "100" } = req.query;
		const match: Record<string, unknown> = {
			route: { $regex: /^\/site-admin/ },
		};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

		const logs = await rawEventModel
			.find(match)
			.sort({ timestamp: -1 })
			.limit(parseInt(limit as string, 10))
			.lean();

		return res
			.status(200)
			.json(standardResponse(true, "Audit logs fetched", logs));
	} catch (err) {
		next(err);
	}
}

export async function getUserActivityLogs(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
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

		const { from, to, limit = "100" } = req.query;
		const match: Record<string, unknown> = { ownerId: userId };
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

		const logs = await rawEventModel
			.find(match)
			.sort({ timestamp: -1 })
			.limit(parseInt(limit as string, 10))
			.lean();

		return res
			.status(200)
			.json(standardResponse(true, "User activity logs fetched", logs));
	} catch (err) {
		next(err);
	}
}

export async function getErrorLogs(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { from, to, limit = "100" } = req.query;
		const match: Record<string, unknown> = {
			statusClass: { $in: ["4xx", "5xx"] },
		};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

		const logs = await rawEventModel
			.find(match)
			.sort({ timestamp: -1 })
			.limit(parseInt(limit as string, 10))
			.lean();

		return res
			.status(200)
			.json(standardResponse(true, "Error logs fetched", logs));
	} catch (err) {
		next(err);
	}
}

export async function getSecurityEvents(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	{ userModel, rawEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { from, to, limit = "100" } = req.query;
		const match: Record<string, unknown> = {
			$or: [
				{ httpStatusCode: 401 },
				{ httpStatusCode: 403 },
				{ error: { $in: ["INVALID_TOKEN", "TOKEN_EXPIRED", "BLACKLISTED", "REVOKED_KEY"] } },
			],
		};
		if (from || to) {
			match.timestamp = {
				...(from ? { $gte: new Date(from as string) } : {}),
				...(to ? { $lte: new Date(to as string) } : {}),
			};
		}

		const events = await rawEventModel
			.find(match)
			.sort({ timestamp: -1 })
			.limit(parseInt(limit as string, 10))
			.lean();

		return res
			.status(200)
			.json(standardResponse(true, "Security events fetched", events));
	} catch (err) {
		next(err);
	}
}
