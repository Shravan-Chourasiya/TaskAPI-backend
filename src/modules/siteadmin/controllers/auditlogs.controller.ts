import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import type { RawAdminEventModel } from "../models/adminEvent.type.js";
import type { SecurityEventModel } from "../models/securityEvent.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { resolveAdminUser, isAdmin } from "../utils/siteAdminController.utils.js";

type RequestWithUser = Request & { userID?: string };

type Deps = {
	userModel: UserStaticMethods;
	adminEventModel: RawAdminEventModel;
	// Only used by getSecurityEvents to union the anonymous 401/403 feed; the
	// other audit-log routes query admin events exclusively.
	securityEventModel?: SecurityEventModel;
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
	{ userModel, adminEventModel }: Deps,
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
		// The collector stores the full path incl. the BASE_URL mount prefix
		// (baseUrl + path), e.g. "/api/v1/site-admin/users/get-all". Only admin
		// events land in this collection, so the route filter is a safety net
		// rather than the primary discriminator.
		const logs = await adminEventModel
			.find({ route: { $regex: /\/site-admin/ }, ...match })
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
	{ userModel, adminEventModel }: Deps,
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
		const logs = await adminEventModel
			.find({ adminId: userId, ...match })
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
	{ userModel, adminEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { match, limit } = auditQuery(req);
		const logs = await adminEventModel
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
	{ userModel, adminEventModel, securityEventModel }: Deps,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { match, limit } = auditQuery(req);

		// Two sources unioned, newest-first:
		//   1. api_admin_events  — admin (JWT) requests that ended 401/403 or with
		//      a security error code (auth'd actor, so the api-key collector never
		//      saw them either — the admin collector recorded them).
		//   2. api_security_events — fully anonymous 401/403 (missing/invalid API
		//      key, expired session, CSRF) captured by securityMetricsCollector.
		//      These previously never reached ANY collection → P3 gap.
		const [adminEvents, anonEvents] = await Promise.all([
			adminEventModel
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
				.lean(),
			securityEventModel
				? securityEventModel
						.find({ ...match })
						.sort({ timestamp: -1 })
						.limit(limit)
						.lean()
				: Promise.resolve([]),
		]);

		// Merge and re-sort by timestamp so the unioned feed stays chronological.
		const events = [...adminEvents, ...anonEvents]
			.sort(
				(a, b) =>
					new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
			)
			.slice(0, limit);

		return res
			.status(200)
			.json(standardResponse(true, "Security events fetched", events));
	} catch (err) {
		next(err);
	}
}
