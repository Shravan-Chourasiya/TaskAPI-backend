import { apiKeyCreationSchema } from "../libs/zod/apikey.zodschema.js";
import {
	apiCreationRL,
	generalApiKeyLimiter,
} from "../middlewares/ratelimiting.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import * as apiKeyController from "../modules/auth/controllers/apikey.controller.js";
import { Router } from "express";

const router = Router();

router.post(
	"/create/apikey",
	apiCreationRL,
	ZodValidatorMiddleware(apiKeyCreationSchema),
	apiKeyController.createApiKey,
);

router.get("/list/apikeys", generalApiKeyLimiter, apiKeyController.listApiKeys);

router.post(
	"/revoke/apikey/:keyId",
	generalApiKeyLimiter,
	apiKeyController.revokeApiKey,
);

export { router as apiKeyRouter } ;
