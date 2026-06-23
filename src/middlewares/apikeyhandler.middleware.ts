import { Request, Response, NextFunction } from "express";
import { standardResponse } from "../utils/apiResponse.utils.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";

export const apikeyHandlerMiddleware = asyncErrorHandler(
	async (req: Request, res: Response, next: NextFunction) => {
		const apiKey = req.headers["x-api-key"] as string | undefined;

		if (!apiKey || typeof apiKey !== "string") {
			return res
				.status(401)
				.json(
					standardResponse(
						false,
						"Unauthorized: API key is missing or invalid",
					),
				);
		}
		next();
	},
);
