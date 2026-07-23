import express from "express";
import type { UserStaticMethods } from "../types/mongoModels/user.type.js";
import type { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import type { SubscriptionStaticMethods } from "../types/mongoModels/subscription.type.js";
import type { SessionStaticMethods } from "../types/mongoModels/session.type.js";
import { strictAuthHandlerFunction } from "../middlewares/tokenhandler.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import {
	userActionSchema,
	modifySubscriptionSchema,
} from "../libs/zod/siteAdmin.zodschema.js";
import * as usersController from "../modules/siteadmin/controllers/users.controller.js";
import * as apiKeysController from "../modules/siteadmin/controllers/apikeys.controller.js";
import * as subscriptionsController from "../modules/siteadmin/controllers/subscriptions.controller.js";
import * as metricsController from "../modules/siteadmin/controllers/metrics.controller.js";
import * as auditlogsController from "../modules/siteadmin/controllers/auditlogs.controller.js";
import * as apistatsController from "../modules/siteadmin/controllers/apistats.controller.js";
import { RawEventModel } from "../modules/metrics/types/rawEvent.type.js";

export function createSiteAdminRouter({
	userModel,
	apiKeyModel,
	subscriptionModel,
	sessionModel,
	rawEventModel,
}: {
	userModel: UserStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
	subscriptionModel: SubscriptionStaticMethods;
	sessionModel: SessionStaticMethods;
	rawEventModel: RawEventModel;
}): express.Router {
	const router = express.Router();

	const strictAuthHandler = createMiddlewareWrapper(
		sessionModel,
		strictAuthHandlerFunction,
		asyncErrorHandler,
	);

	router.use(strictAuthHandler);

	// ── Users ──────────────────────────────────────────────────────────────────

	router.get("/users/get-all", (req, res, next) =>
		usersController.getAllUsers(req, res, next, userModel),
	);

	router.post("/users/create", (req, res, next) =>
		usersController.createUser(req, res, next, userModel),
	);

	router.patch("/users/modify", (req, res, next) =>
		usersController.modifyUser(req, res, next, userModel),
	);

	router.patch("/users/force-password-reset", (req, res, next) =>
		usersController.forcePasswordReset(req, res, next, userModel),
	);

	router.patch("/users/assign-role", (req, res, next) =>
		usersController.assignUserRole(req, res, next, userModel),
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
		apiKeysController.getUserApiKeys(req, res, next, {
			userModel,
			apiKeyModel,
		}),
	);

	router.patch("/api-keys/:keyId/revoke", (req, res, next) =>
		apiKeysController.revokeApiKey(req, res, next, { userModel, apiKeyModel }),
	);

	router.patch("/api-keys/:keyId/blacklist", (req, res, next) =>
		apiKeysController.blacklistApiKey(req, res, next, {
			userModel,
			apiKeyModel,
		}),
	);

	router.post("/users/:userId/api-keys", (req, res, next) =>
		apiKeysController.createUserApiKey(req, res, next, {
			userModel,
			apiKeyModel,
		}),
	);

	router.delete("/api-keys/:keyId", (req, res, next) =>
		apiKeysController.deleteApiKey(req, res, next, { userModel, apiKeyModel }),
	);
	router.patch("/api-keys/:keyId/restore", (req, res, next) =>
		apiKeysController.restoreApiKey(req, res, next, { userModel, apiKeyModel }),
	);

	router.patch("/api-keys/:keyId/modify", (req, res, next) =>
		apiKeysController.modifyApiKey(req, res, next, { userModel, apiKeyModel }),
	);

	router.patch("/api-keys/:keyId/rotate", (req, res, next) =>
		apiKeysController.rotateApiKey(req, res, next, { userModel, apiKeyModel }),
	);

	router.patch("/api-keys/:keyId/whitelist", (req, res, next) =>
		apiKeysController.whitelistApiKey(req, res, next, {
			userModel,
			apiKeyModel,
		}),
	);

	// ── Subscription nested under user ─────────────────────────────────────────
	router.post("/users/subscription", (req, res, next) =>
		subscriptionsController.createUserSubscription(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);

	router.delete("/users/:userId/subscription/delete", (req, res, next) =>
		subscriptionsController.deleteUserSubscription(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);
	router.patch("/users/:userId/subscription/blacklist", (req, res, next) =>
		subscriptionsController.blacklistUserSubscription(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);
	router.patch("/users/:userId/subscription/suspend", (req, res, next) =>
		subscriptionsController.suspendUserSubscription(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);

	router.patch("/users/:userId/subscription/restore", (req, res, next) =>
		subscriptionsController.restoreUserSubscription(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);

	router.patch("/users/:userId/subscription/extend", (req, res, next) =>
		subscriptionsController.extendUserTrial(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);

	router.patch("/users/:userId/subscription/expire", (req, res, next) =>
		subscriptionsController.expireUserSubscription(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);

	router.patch("/users/:userId/subscription/change-plan", (req, res, next) =>
		subscriptionsController.changeUserSubscriptionTier(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);

	router.get("/users/:userId/subscription/", (req, res, next) =>
		subscriptionsController.getUserSubscription(req, res, next, {
			userModel,
			subscriptionModel,
		}),
	);

	router.patch(
		"/users/:userId/subscription/modify",
		ZodValidatorMiddleware(modifySubscriptionSchema),
		(req, res, next) =>
			subscriptionsController.modifyUserSubscription(req, res, next, {
				userModel,
				subscriptionModel,
			}),
	);

	// ── Metrics API routes ─────────────────────────────────────────
	router.get("/metrics/user-growth", (req, res, next) =>
		metricsController.getUserGrowthMetrics(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/metrics/engagement", (req, res, next) =>
		metricsController.getEngagementMetrics(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/metrics/feature-usage", (req, res, next) =>
		metricsController.getFeatureUsageStats(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/metrics/subscription-trends", (req, res, next) =>
		metricsController.getSubscriptionTrends(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/metrics/export", (req, res, next) =>
		metricsController.exportMetrics(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/metrics/report", (req, res, next) =>
		metricsController.generateReport(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);

	// ── API Statistics API routes ─────────────────────────────────────────
	router.get("/api-stats/usage", (req, res, next) =>
		apistatsController.getApiUsageStats(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/api-stats/latency", (req, res, next) =>
		apistatsController.getApiLatencyStats(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/api-stats/errors", (req, res, next) =>
		apistatsController.getApiErrorStats(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/api-stats/traffic/:userId", (req, res, next) =>
		apistatsController.getApiTrafficByUser(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);

	// ── Audit Logs API routes ─────────────────────────────────────────

	router.get("/audit-logs", (req, res, next) =>
		auditlogsController.getAdminAuditLogs(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/audit-logs/user/:userId", (req, res, next) =>
		auditlogsController.getUserActivityLogs(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/audit-logs/errors", (req, res, next) =>
		auditlogsController.getErrorLogs(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);
	router.get("/audit-logs/security-events", (req, res, next) =>
		auditlogsController.getSecurityEvents(req, res, next, {
			userModel,
			rawEventModel,
		}),
	);

	return router;
}
