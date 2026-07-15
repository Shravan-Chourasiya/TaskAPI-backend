import express from "express";
import type { UserStaticMethods } from "../types/mongoModels/user.type.js";
import type { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import type { SubscriptionStaticMethods } from "../types/mongoModels/subscription.type.js";
import type { SessionStaticMethods } from "../types/mongoModels/session.type.js";
import { strictAuthHandlerFunction } from "../middlewares/tokenhandler.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import { userActionSchema, modifySubscriptionSchema } from "../libs/zod/siteAdmin.zodschema.js";
import * as usersController from "../modules/siteadmin/controllers/users.controller.js";
import * as apiKeysController from "../modules/siteadmin/controllers/apikeys.controller.js";
import * as subscriptionsController from "../modules/siteadmin/controllers/subscriptions.controller.js";

export function createSiteAdminRouter({
	userModel,
	apiKeyModel,
	subscriptionModel,
	sessionModel,
}: {
	userModel: UserStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
	subscriptionModel: SubscriptionStaticMethods;
	sessionModel: SessionStaticMethods;
}): express.Router {
	const router = express.Router();

	const strictAuthHandler = createMiddlewareWrapper(
		sessionModel,
		strictAuthHandlerFunction,
		asyncErrorHandler,
	);

	router.use(strictAuthHandler);

	// ── Users ──────────────────────────────────────────────────────────────────

	router.get("/users", (req, res, next) =>
		usersController.getAllUsers(req, res, next, userModel),
	);

	// filter via ?status=suspended  (was /users/filter/:status)
	router.get("/users/filter", (req, res, next) =>
		usersController.getFilteredUsers(req, res, next, userModel),
	);

	router.get("/users/:userId", (req, res, next) =>
		usersController.getUserById(req, res, next, userModel),
	);

	router.patch(
		"/users/:userId/status",
		ZodValidatorMiddleware(userActionSchema),
		(req, res, next) => usersController.userAction(req, res, next, userModel),
	);

	router.patch("/users/:userId/restore", (req, res, next) =>
		usersController.restoreUser(req, res, next, userModel),
	);

	// ── API Keys nested under user ─────────────────────────────────────────────

	router.get("/users/:userId/api-keys", (req, res, next) =>
		apiKeysController.getUserApiKeys(req, res, next, { userModel, apiKeyModel }),
	);

	router.patch("/api-keys/:keyId/revoke", (req, res, next) =>
		apiKeysController.revokeApiKey(req, res, next, { userModel, apiKeyModel }),
	);

	router.patch("/api-keys/:keyId/blacklist", (req, res, next) =>
		apiKeysController.blacklistApiKey(req, res, next, { userModel, apiKeyModel }),
	);

	// ── Subscription nested under user ─────────────────────────────────────────

	router.get("/users/:userId/subscription", (req, res, next) =>
		subscriptionsController.getUserSubscription(req, res, next, { userModel, subscriptionModel }),
	);

	router.patch(
		"/users/:userId/subscription",
		ZodValidatorMiddleware(modifySubscriptionSchema),
		(req, res, next) => subscriptionsController.modifyUserSubscription(req, res, next, { userModel, subscriptionModel }),
	);

	return router;
}
