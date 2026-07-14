import type { Request, Response } from "express";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";

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
