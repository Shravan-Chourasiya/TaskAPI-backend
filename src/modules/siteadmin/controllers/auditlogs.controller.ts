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

// Record-level audit logs paginate with an ISO timestamp cursor: docs are
// sorted timestamp desc, so pass the last seen document's timestamp as
// ?cursor= to fetch the next page. limit is hard-capped at 1000.
function auditQuery(req: Request): { match: Record<string, unknown>; limit: number } {
	const { from, to, cursor, limit = "100" } = req.query;
	const cap = Math.min(parseInt(limit as string, 10) || 100, 1000);

	const match: Record<string, unknown> = {};
	if (from || to || cursor) {
		const ts: Record<string, Date> = {};
		if (cursor) ts.$lt = new Date(cursor as string);
		if (from) ts.$gte = new Date(from as string);
		if (to) ts.$lte = new Date(to as string);
		match.timestamp = ts;
	}

	return { match, limit: cap };
}

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

		const { match, limit } = auditQuery(req);
		const logs = await rawEventModel
			.find({ route: { $regex: /^\/site-admin/ }, ...match })
			.sort({ timestamp: -1 })
			.limit(limit)
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

		const { match, limit } = auditQuery(req);
		const logs = await rawEventModel
			.find({ ownerId: userId, ...match })
			.sort({ timestamp: -1 })
			.limit(limit)
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

		const { match, limit } = auditQuery(req);
		const logs = await rawEventModel
			.find({ statusClass: { $in: ["4xx", "5xx"] }, ...match })
			.sort({ timestamp: -1 })
			.limit(limit)
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

		const { match, limit } = auditQuery(req);
		const events = await rawEventModel
			.find({
				$or: [
					{ httpStatusCode: 401 },
					{ httpStatusCode: 403 },
					{ error: { $in: ["INVALID_TOKEN", "TOKEN_EXPIRED", "BLACKLISTED", "REVOKED_KEY"] } },
				],
				...match,
			})
			.sort({ timestamp: -1 })
			.limit(limit)
			.lean();

		return res
			.status(200)
			.json(standardResponse(true, "Security events fetched", events));
	} catch (err) {
		next(err);
	}
}
