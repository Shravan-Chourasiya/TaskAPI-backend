import type { Request, NextFunction, Response } from "express";
import type { ClientUserStaticMethods } from "../types/userMongo.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import z from "zod";
import {
	adminAddNewUserSchema,
	AdminEditableClientUserDataType,
	adminModifyUserSchema,
} from "../../../libs/zod/clientAdmin.zodschema.js";
import { resolveClientId } from "../utils/clientAdminController.utils.js";

type RequestWithApiOwner = Request & { apiOwnerId?: string };
type RequestWithApiOwnerAndUserData = RequestWithApiOwner & {
	userNewData?: AdminEditableClientUserDataType;
};

export async function getAllUsersList(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const clientId = resolveClientId(req, res);
		if (!clientId) return;

		const users = await clientUserModel.find({ clientId }).lean();
		if (!users || users.length === 0) {
			return res
				.status(404)
				.json(standardResponse(false, "No users found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "Users fetched successfully", users));
	} catch (err: any) {
		next(err);
	}
}

export async function getFilteredUsersList(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const { f } = req.params;
		if (!f || f === "") {
			return res
				.status(400)
				.json(standardResponse(false, "Fill missing fields", null));
		}

		const clientId = resolveClientId(req, res);
		if (!clientId) return;

		const users = await clientUserModel.find({ clientId, status: f }).lean();
		if (!users || users.length === 0) {
			return res
				.status(404)
				.json(standardResponse(false, "No users found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "Users fetched successfully", users));
	} catch (err: any) {
		next(err);
	}
}

export async function modifyUser(
	req: RequestWithApiOwnerAndUserData,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const { userId } = req.params;
		const { userNewData }: z.infer<typeof adminModifyUserSchema> = req.body;

		const clientId = resolveClientId(req, res);
		if (!clientId) return;

		if (!userId || !userNewData) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required fields", null));
		}

		const targetUser = await clientUserModel.findOneAndUpdate(
			{ clientId, _id: userId },
			{ $set: userNewData },
			{ new: true },
		);
		if (!targetUser) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		return res
			.status(200)
			.json(standardResponse(true, "User updated successfully", targetUser));
	} catch (err: any) {
		next(err);
	}
}

export async function addUser(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const { newUserData }: z.infer<typeof adminAddNewUserSchema> = req.body;
		const clientId = resolveClientId(req, res);
		if (!clientId) return;

		if (!newUserData) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required fields", null));
		}

		const { verifiedAt, ...restNewUserData } = newUserData;
		const newUserCreated = await clientUserModel.create({
			clientId,
			...restNewUserData,
			...(verifiedAt !== undefined && { verifiedAt }),
		});

		return res
			.status(201)
			.json(standardResponse(true, "User added successfully", newUserCreated));
	} catch (err: any) {
		next(err);
	}
}

export async function deleteUser(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const { userId } = req.params;

		const clientId = resolveClientId(req, res);
		if (!clientId) return;

		if (!userId) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing Required Data", null));
		}

		const userToDelete = await clientUserModel.findOneAndUpdate(
			{ clientId, _id: userId },
			{
				isDeleted: true,
				status: "deleted",
				lastActiveAt: new Date(),
				deletedAt: new Date(),
				scheduledDeletionAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
			},
			{ new: true },
		);
		if (!userToDelete) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		const deletedUser = await clientUserModel.deleteOne({
			clientId,
			_id: userId,
		});
		return res
			.status(200)
			.json(standardResponse(true, "User Deleted Successfully!", deletedUser));
	} catch (err: any) {
		next(err);
	}
}

export async function blackListOrBlockUser(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const { id } = req.params;
		const { blackListReason }: { blackListReason?: string } = req.body;

		const clientId = resolveClientId(req, res);
		if (!clientId) return;

		if (!id) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing Required Data", null));
		}

		const blackListedUser = await clientUserModel.findOneAndUpdate(
			{ clientId, _id: id },
			{
				isDeleted: true,
				status: "blacklisted",
				blackListReason: blackListReason || "No reason provided",
				blackListedAt: new Date(),
				lastActiveAt: new Date(),
			},
			{ new: true },
		);
		if (!blackListedUser) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}

		return res
			.status(200)
			.json(
				standardResponse(
					true,
					"User Blacklisted Successfully!",
					blackListedUser,
				),
			);
	} catch (err: any) {
		next(err);
	}
}

export async function unBlackListUser(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const { id } = req.params;

		const clientId = resolveClientId(req, res);
		if (!clientId) return;

		if (!id) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing Required Data", null));
		}

		const unBlacklistedUser = await clientUserModel.findOneAndUpdate(
			{ clientId, _id: id, status: "blacklisted" },
			{
				isDeleted: false,
				status: "active",
				blackListReason: null,
				blackListedAt: null,
				lastActiveAt: new Date(),
			},
			{ new: true },
		);
		if (!unBlacklistedUser) {
			return res
				.status(404)
				.json(
					standardResponse(false, "User not found or not blacklisted", null),
				);
		}

		return res
			.status(200)
			.json(
				standardResponse(
					true,
					"User Unblacklisted Successfully!",
					unBlacklistedUser,
				),
			);
	} catch (err: any) {
		next(err);
	}
}
