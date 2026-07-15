import {
	apiKeyCreationSchema,
	updateApiKeySchema,
} from "../libs/zod/apikey.zodschema.js";
import {
	apiCreationLimiter,
	apiKeyUpdateLimiter,
	generalApiKeyLimiter,
} from "../middlewares/ratelimiting.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import * as apiKeyController from "../modules/auth/controllers/apikey.controller.js";
import { Router } from "express";

export function createApiKeyRouter({
	userModel,
	apiKeyModel,
}: {
	userModel: any;
	apiKeyModel: any;
}): Router {
	const router = Router();

	router.post(
		"/",
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

	router.get("/", generalApiKeyLimiter, (req, res, next) =>
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

	router.delete("/:keyId", generalApiKeyLimiter, (req, res, next) =>
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
