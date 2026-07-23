import {
	apiKeyCreationSchema,
	updateApiKeySchema,
} from "../libs/zod/apikey.zodschema.js";
import {
	apiCreationLimiter,
	apiKeyUpdateLimiter,
	generalApiKeyLimiter,
} from "../middlewares/ratelimiting.middleware.js";
import { accessTokenHandlerFunction } from "../middlewares/tokenhandler.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import * as apiKeyController from "../modules/auth/controllers/apikey.controller.js";
import { Router } from "express";

export function createApiKeyRouter({
	userModel,
	apiKeyModel,
	sessionModel,
}: {
	userModel: any;
	apiKeyModel: any;
	sessionModel: any;
}): Router {
	const accessTokenHandler = createMiddlewareWrapper(
		sessionModel,
		accessTokenHandlerFunction,
		asyncErrorHandler,
	);
	const router = Router();

	router.post(
		"/",
		accessTokenHandler,
		apiCreationLimiter,
		ZodValidatorMiddleware(apiKeyCreationSchema),
		(req, res, next) =>
			apiKeyController.createApiKeyController(
				req,
				res,
				next,
				userModel,
				apiKeyModel,
			),
	);

	router.get("/", accessTokenHandler, generalApiKeyLimiter, (req, res, next) =>
		apiKeyController.listApiKeysController(
			req,
			res,
			next,
			userModel,
			apiKeyModel,
		),
	);

	router.patch(
		"/:keyId",
		accessTokenHandler,
		apiKeyUpdateLimiter,
		ZodValidatorMiddleware(updateApiKeySchema),
		(req, res, next) =>
			apiKeyController.updateApiKeyController(
				req,
				res,
				next,
				userModel,
				apiKeyModel,
			),
	);

	router.delete(
		"/:keyId",
		accessTokenHandler,
		generalApiKeyLimiter,
		(req, res, next) =>
			apiKeyController.deleteApiKeyController(
				req,
				res,
				next,
				userModel,
				apiKeyModel,
			),
	);

	return router;
}
