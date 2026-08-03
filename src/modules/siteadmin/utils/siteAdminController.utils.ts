import type { Request, Response } from "express";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import { AppError } from "../../../types/errors.interface.js";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";

// ─── Hard window cap for raw_events queries ───────────────────────────────────
// Per-dimension site-admin routes (route/error/latency breakdowns) keep reading
// raw_events because rollups only carry time-bucket aggregates. Scanning raw at
// 90-day volume is the exact cost the rollup migration removes, so those routes
// are capped at 7 days — a caller asking for more gets a hard 400, not a soft
// truncation that silently changes what admin analytics show.
const MAX_RAW_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

export function applyHardWindowCap(from?: Date, to?: Date): void {
	if (!from && !to) return; // no window requested — leave to the route default

	const f = from ?? new Date(to!.getTime() - MAX_RAW_WINDOW_MS);
	const t = to ?? new Date(f.getTime() + MAX_RAW_WINDOW_MS);

	if (t.getTime() - f.getTime() > MAX_RAW_WINDOW_MS) {
		throw new AppError(
			"WINDOW_TOO_LARGE",
			"Window too large. Maximum 7 days for route/dimension analytics.",
			400,
		);
	}
}

type RequestWithUser = Request & { userID?: string };
type AdminRole = "admin" | "moderator";

export type ResolvedAdmin = {
	userId: string;
	role: AdminRole;
};

export async function resolveAdminUser(
	req: RequestWithUser,
	res: Response,
	userModel: UserStaticMethods,
): Promise<ResolvedAdmin | null> {
	const userId = req.userID;
	if (!userId) {
		res.status(401).json(standardResponse(false, "Unauthorized", null));
		return null;
	}

	const user = await userModel.findById(userId).select("roles status");
	if (!user) {
		res.status(401).json(standardResponse(false, "Unauthorized", null));
		return null;
	}
	if (user.status !== "active") {
		res.status(403).json(standardResponse(false, "Account is not active", null));
		return null;
	}

	// roles is stored as string[] in the schema
	const rolesArr = Array.isArray(user.role) ? user.role : [user.role];
	const role: AdminRole | null = rolesArr.includes("admin")
		? "admin"
		: rolesArr.includes("moderator")
		? "moderator"
		: null;

	if (!role) {
		res.status(403).json(standardResponse(false, "Forbidden: insufficient permissions", null));
		return null;
	}

	return { userId, role };
}

export function isAdmin(admin: ResolvedAdmin): boolean {
	return admin.role === "admin";
}
