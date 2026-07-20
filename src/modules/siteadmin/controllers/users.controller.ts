import crypto from "crypto";
import type { Request, NextFunction, Response } from "express";
import type { UserStaticMethods } from "../../../types/mongoModels/user.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import {
	resolveAdminUser,
	isAdmin,
} from "../utils/siteAdminController.utils.js";
import z from "zod";
import { userActionSchema } from "../../../libs/zod/siteAdmin.zodschema.js";
import type { UserRole } from "../../../constants.js";
import { ROLE_RANK } from "../../../constants.js";

type RequestWithUser = Request & { userID?: string };

export async function getAllUsers(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const users = await userModel
			.find({})
			.select("-passwordHash -lastPassword -twoFASecret")
			.lean();
		if (!users || users.length === 0) {
			return res
				.status(404)
				.json(standardResponse(false, "No users found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "Users fetched successfully", users));
	} catch (err) {
		next(err);
	}
}

export async function getFilteredUsers(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const status = req.query.status;
		if (!status || typeof status !== "string" || status.trim() === "") {
			return res
				.status(400)
				.json(standardResponse(false, "Status filter is required", null));
		}

		const users = await userModel
			.find({ status })
			.select("-passwordHash -lastPassword -twoFASecret")
			.lean();
		if (!users || users.length === 0) {
			return res
				.status(404)
				.json(standardResponse(false, "No users found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "Users fetched successfully", users));
	} catch (err) {
		next(err);
	}
}

export async function getUserById(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { userId } = req.params;
		const user = await userModel
			.findById(userId)
			.select("-passwordHash -lastPassword -twoFASecret")
			.lean();
		if (!user) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "User fetched successfully", user));
	} catch (err) {
		next(err);
	}
}

export async function userAction(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		const { userId } = req.params;
		const { action, reason }: z.infer<typeof userActionSchema> = req.body;

		// moderators can only suspend
		if (!isAdmin(admin) && action !== "suspend") {
			return res
				.status(403)
				.json(
					standardResponse(false, "Moderators can only suspend users", null),
				);
		}

		const now = new Date();
		let update: Record<string, unknown> = {};

		switch (action) {
			case "suspend":
				update = { status: "suspended" };
				break;
			case "blacklist":
				update = {
					status: "suspended",
					isBlackListed: true,
					blackListReason: reason || "No reason provided",
					blackListedAt: now,
				};
				break;
			case "delete":
				update = {
					isDeleted: true,
					status: "deleted",
					deletedAt: now,
					deletedBy: admin.userId,
					scheduledDeletionAt: new Date(
						now.getTime() + 30 * 24 * 60 * 60 * 1000,
					),
				};
				break;
		}

		const updated = await userModel
			.findByIdAndUpdate(userId, { $set: update }, { new: true })
			.select("-passwordHash -lastPassword -twoFASecret");
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, `User ${action} successful`, updated));
	} catch (err) {
		next(err);
	}
}

export async function restoreUser(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;

		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can restore users", null));
		}

		const { userId } = req.params;
		const updated = await userModel
			.findByIdAndUpdate(
				userId,
				{
					$set: { isDeleted: false, status: "active", isBlackListed: false },
					$unset: {
						deletedAt: "",
						scheduledDeletionAt: "",
						blackListReason: "",
						blackListedAt: "",
					},
				},
				{ new: true },
			)
			.select("-passwordHash -lastPassword -twoFASecret");

		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "User restored successfully", updated));
	} catch (err) {
		next(err);
	}
}
// ================================================ NEWLY ADDED =============================================
export async function modifyUser(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can modify users", null));
		}

		const { userId } = req.params;
		const { username, email, phone, profile } = req.body;

		const updates: Record<string, unknown> = {};
		if (username !== undefined) updates.username = username;
		if (email !== undefined) updates.email = email;
		if (phone !== undefined) updates.phone = phone;
		if (profile !== undefined) updates.profile = profile;

		if (Object.keys(updates).length === 0) {
			return res
				.status(400)
				.json(standardResponse(false, "No fields provided for update", null));
		}

		const updated = await userModel
			.findByIdAndUpdate(userId, { $set: updates }, { new: true, runValidators: true })
			.select("-passwordHash -lastPassword -twoFASecret");
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "User updated successfully", updated));
	} catch (err) {
		next(err);
	}
}

export async function createUser(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can create users", null));
		}

		const { username, email, password, role } = req.body;
		if (!username || !email || !password) {
			return res
				.status(400)
				.json(standardResponse(false, "username, email and password are required", null));
		}

		const existing = await userModel.findByEmail(email);
		if (existing) {
			return res
				.status(409)
				.json(standardResponse(false, "Email already in use", null));
		}

		const user = await userModel.create({
			username,
			email,
			passwordHash: password,
			role: role ?? "user",
			status: "active",
			isVerified: true,
			verifiedAt: new Date(),
			subscriptionType: "Free",
		});

		return res.status(201).json(
			standardResponse(true, "User created successfully", {
				userId: user._id,
				username: user.username,
				email: user.email,
			}),
		);
	} catch (err) {
		next(err);
	}
}

export async function forcePasswordReset(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can force password resets", null));
		}

		const { userId } = req.params;
		const tempPassword = `$2${req.body.tempPassword}`;

		const user = await userModel.findById(userId);
		if (!user) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		user.passwordHash = tempPassword;
		user.lastPasswordChangedAt = new Date();
		await user.save();

		return res.status(200).json(
			standardResponse(true, "Password reset successfully", { tempPassword }),
		);
	} catch (err) {
		next(err);
	}
}

export async function assignUserRole(
	req: RequestWithUser,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
) {
	try {
		const admin = await resolveAdminUser(req, res, userModel);
		if (!admin) return;
		if (!isAdmin(admin)) {
			return res
				.status(403)
				.json(standardResponse(false, "Only admins can assign roles", null));
		}

		const { userId } = req.params;
		const { role }: { role: UserRole } = req.body;

		if (!role || !(role in ROLE_RANK)) {
			return res
				.status(400)
				.json(standardResponse(false, "Invalid role", null));
		}

		const updated = await userModel
			.findByIdAndUpdate(userId, { $set: { role } }, { new: true })
			.select("-passwordHash -lastPassword -twoFASecret");
		if (!updated) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "Role assigned successfully", updated));
	} catch (err) {
		next(err);
	}
}
