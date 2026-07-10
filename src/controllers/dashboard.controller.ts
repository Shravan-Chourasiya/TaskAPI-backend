import type { NextFunction, Request, Response } from "express";
import { UserStaticMethods } from "../types/mongoModels/user.type.js";
import { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import { ClientUserStaticMethods } from "../modules/clientauth/types/userMongo.type.js";
import { IRollupBucket } from "../modules/metrics/types/rollupData.type.js";
import { Model } from "mongoose";
import jwt, { JwtPayload } from "jsonwebtoken";
import { config } from "../configs/app.config.js";
import { standardResponse } from "../utils/apiResponse.utils.js";

type RequestWithApiOwner = Request & { apiOwnerId?: string };

export async function getAllApiMetricsController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
	apiKeyModel: ApiKeyStaticMethods,
	clientUserModel: ClientUserStaticMethods,
	Rollup5m: Model<IRollupBucket>,
	Rollup1h: Model<IRollupBucket>,
	Rollup1d: Model<IRollupBucket>,
) {
	try {
		if (!req.cookies.acToken || req.cookies.acToken === "") {
			return res
				.status(403)
				.json(standardResponse(false, "Invalid Access Token!"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const isuser = await userModel.findById(decoded.id);
		if (!isuser) {
			return res.status(404).json(standardResponse(false, "User not found!"));
		}

		const hasCreatedApiKey = await apiKeyModel
			.find({ ownerId: isuser._id })
			.countDocuments();
		if (!hasCreatedApiKey || hasCreatedApiKey == 0) {
			return res
				.status(404)
				.json(standardResponse(false, "No APIKEY found for user!"));
		}

		const hasRegisteredUser = await clientUserModel
			.find({ ownerId: isuser._id })
			.countDocuments();
		if (!hasRegisteredUser || hasRegisteredUser == 0) {
			return res
				.status(404)
				.json(
					standardResponse(
						false,
						"No Registered User found with the OwnerId (ClientId)",
					),
				);
		}
	} catch (err: any) {
		next(err);
	}
}
export async function getSpecificApiMetricsController(
	req: RequestWithApiOwner,
	res: Response,
	next: NextFunction,
	userModel: UserStaticMethods,
	apiKeyModel: ApiKeyStaticMethods,
	clientUserModel: ClientUserStaticMethods,
	Rollup5m: Model<IRollupBucket>,
	Rollup1h: Model<IRollupBucket>,
	Rollup1d: Model<IRollupBucket>,
) {
	try {
		const apiId = req.params;
		if (!apiId) {
			return res
				.status(404)
				.json(
					standardResponse(false, "ApikeyId is missing ( pass it in th Url)!"),
				);
		}

		if (!req.cookies.acToken || req.cookies.acToken === "") {
			return res
				.status(403)
				.json(standardResponse(false, "Invalid Access Token!"));
		}

		const decoded = jwt.verify(
			req.cookies.acToken,
			config.ACCESS_TOKEN_JWT_SECRET,
		) as JwtPayload;

		const isuser = await userModel.findById(decoded.id);
		if (!isuser) {
			return res.status(404).json(standardResponse(false, "User not found!"));
		}

		const hasCreatedApiKey = await apiKeyModel.findById({ apiId });
		if (!hasCreatedApiKey) {
			return res
				.status(404)
				.json(standardResponse(false, "No APIKEY found for user with given Id !"));
		}

		const hasRegisteredUser = await clientUserModel
			.find({ ownerId: isuser._id })
			.countDocuments();
		if (!hasRegisteredUser || hasRegisteredUser == 0) {
			return res
				.status(404)
				.json(
					standardResponse(
						false,
						"No Registered User found with the OwnerId (ClientId)",
					),
				);
		}

        
	} catch (err: any) {
		next(err);
	}
}
