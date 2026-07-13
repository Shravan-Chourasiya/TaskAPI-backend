import type { Request, NextFunction, Response } from "express";
import {
	ClientUser,
	ClientUserDocument,
	ClientUserStaticMethods,
} from "../types/userMongo.type.js";
import { standardResponse } from "../../../utils/apiResponse.utils.js";
import z, { string } from "zod";
import {
	adminAddNewUserSchema,
	AdminEditableClientUserDataType,
	adminModifyUserSchema,
} from "../../../libs/zod/clientAdmin.zodschema.js";

type RequestWithClientId = Request & { clientId?: string; apiKeyId?: string };
type RequestWithClientIdandUserData = RequestWithClientId & {
	userNewData?: AdminEditableClientUserDataType;
};

export async function getAllUsersList(
	req: RequestWithClientId,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		if (!req.clientId) {
			return res
				.status(403)
				.json(
					standardResponse(false, "Client ID is missing in the request", null),
				);
		}

		const users = await clientUserModel.find({ clientId: req.clientId }).lean();
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
	req: RequestWithClientId,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const { f } = req.params;
		if (!f || f === "" || f[0]?.trim() === "") {
			return res
				.status(400)
				.json(standardResponse(false, "Fill missing fields", null));
		}

		if (!req.apiKeyId) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing fields in Request", null));
		}
		if (!req.clientId) {
			return res
				.status(403)
				.json(
					standardResponse(
						false,
						"You are not authorized to perform this action",
						null,
					),
				);
		}

		if (f && req.apiKeyId && req.clientId) {
			const users = await clientUserModel
				.find({
					clientId: req.clientId,
					apiKeyId: req.apiKeyId,
					status: f,
				})
				.lean();
			if (!users || users.length === 0) {
				return res
					.status(404)
					.json(standardResponse(false, "No users found", null));
			}
			return res
				.status(200)
				.json(standardResponse(true, "Users fetched successfully", users));
		} else if (f && req.clientId) {
			const users = await clientUserModel
				.find({
					clientId: req.clientId,
					status: f,
				})
				.lean();
			if (!users || users.length === 0) {
				return res
					.status(404)
					.json(standardResponse(false, "No users found", null));
			}
			return res
				.status(200)
				.json(standardResponse(true, "Users fetched successfully", users));
		}
	} catch (err: any) {
		next(err);
	}
}

export async function modifyUser(
	req: RequestWithClientIdandUserData,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const userToModifyId = req.params;
		const { clientId, userNewData }: z.infer<typeof adminModifyUserSchema> =
			req.body;

		if (!clientId || !userToModifyId || !userNewData) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing required fields", null));
		}

		const targetUser = await clientUserModel.findOneAndUpdate(
			{ clientId, _id: userToModifyId },
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
	req: RequestWithClientId,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const {
			clientId,
			apiKeyId,
			newUserData,
		}: z.infer<typeof adminAddNewUserSchema> = req.body;
		if (!clientId || !apiKeyId || !newUserData) {
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

		if (!newUserCreated) {
			return res
				.status(500)
				.json(standardResponse(false, "Failed to create user", null));
		}
		return res
			.status(201)
			.json(standardResponse(true, "User added successfully", newUserCreated));
	} catch (err: any) {
		next(err);
	}
}

export async function deleteUser(
	req: RequestWithClientId,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const toBeDeletedUserId = req.params;
		if (!toBeDeletedUserId || !req.clientId) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing Required Data", null));
		}
		const userToDelete = await clientUserModel.findOneAndUpdate(
			{
				clientId: req.clientId,
				_id: toBeDeletedUserId,
			},
			{
				isDeleted: true,
				status: "deleted",
				lastActiveAt: new Date(),
				deletedAt: new Date(),
				scheduledDeletionAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // Schedule deletion after 30 days
			},
			{ new: true },
		);
		if (!userToDelete) {
			return res
				.status(404)
				.json(standardResponse(false, "User not found", null));
		}
		const deletedUser = await clientUserModel.deleteOne({
			clientId: req.clientId,
			_id: toBeDeletedUserId,
		});
		if (!deletedUser) {
			return res
				.status(500)
				.json(standardResponse(false, "Failed to delete User", null));
		}
		return res
			.status(200)
			.json(standardResponse(true, "User Deleted Successfully!", deletedUser));
	} catch (err: any) {
		next(err);
	}
}

export async function blackListOrBlockUser(
	req: RequestWithClientId,
	res: Response,
	next: NextFunction,
	clientUserModel: ClientUserStaticMethods,
) {
	try {
		const toBeDeletedUserId = req.params;
		const { blackListReason }: { blackListReason?: string } = req.body;
		if (!toBeDeletedUserId || !req.clientId) {
			return res
				.status(400)
				.json(standardResponse(false, "Missing Required Data", null));
		}
		const blackListedUser = await clientUserModel.findOneAndUpdate(
			{
				clientId: req.clientId,
				_id: toBeDeletedUserId,
			},
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
