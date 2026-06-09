import {
	apiKeyCreationSchema,
	updateApiKeySchema,
} from "../libs/zod/apikey.zodschema.js";
import {
	apiCreationRL,
	apiKeyUpdateLimiter,
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
	apiKeyController.createApiKeyController,
);

router.get(
	"/list/apikeys",
	generalApiKeyLimiter,
	apiKeyController.listApiKeysController,
);

router.post(
	"/revoke/apikey/:keyId",
	generalApiKeyLimiter,
	apiKeyController.revokeApiKeyController,
);

router.patch(
	"/update",
	apiKeyUpdateLimiter,
	ZodValidatorMiddleware(updateApiKeySchema),
	apiKeyController.updateApiKeyController,
);
router.patch(
	"/update/name",
	apiKeyUpdateLimiter,
	ZodValidatorMiddleware(updateApiKeySchema),
	apiKeyController.updateApiKeyNameController,
);
router.patch(
	"/update/scopes",
	apiKeyUpdateLimiter,
	ZodValidatorMiddleware(updateApiKeySchema),
	apiKeyController.updateApiKeyScopesController,
);
router.patch(
	"/update/ips",
	apiKeyUpdateLimiter,
	ZodValidatorMiddleware(updateApiKeySchema),
	apiKeyController.updateApiKeyIPWhiteListController,
);

router.delete(
	"/delete/:keyId",
	generalApiKeyLimiter,
	apiKeyController.deleteApiKeyController,
);

export { router as apiKeyRouter };
