import express from "express";
import { ClientUserStaticMethods } from "../modules/clientauth/types/userMongo.type.js";
import { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import { IRollupBucket } from "../modules/metrics/types/rollupData.type.js";
import { UserStaticMethods } from "../types/mongoModels/user.type.js";
import { Model } from "mongoose";
import { apikeyHandlerFunction } from "../middlewares/apikeyhandler.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";
import { clientApiRateLimiter } from "../modules/clientauth/utils/rateLimiters.js";
import * as dashboardControllers from "../controllers/dashboard.controller.js";

export function createDashboardRouter({
	userModel,
	apiKeyModel,
	clientUserModel,
	Rollup5m,
	Rollup1h,
	Rollup1d,
}: {
	userModel: UserStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
	clientUserModel: ClientUserStaticMethods;
	Rollup5m: Model<IRollupBucket>;
	Rollup1h: Model<IRollupBucket>;
	Rollup1d: Model<IRollupBucket>;
}): express.Router {
	const apikeyHandler = createMiddlewareWrapper(
		apiKeyModel,
		apikeyHandlerFunction,
		asyncErrorHandler,
	);

	const router: express.Router = express.Router();

	// All client routes are protected by API key + general rate limiter
	router.use(apikeyHandler, clientApiRateLimiter);

	router.get("/client/all-apis", (req, res, next) =>
		dashboardControllers.getAllApiMetricsController(
			req,
			res,
			next,
			userModel,
			apiKeyModel,
			clientUserModel,
			Rollup5m,
			Rollup1h,
			Rollup1d,
		),
	);

	router.get("/client/all-apis/:apikeyid", (req, res, next) =>
		dashboardControllers.getSpecificApiMetricsController(
			req,
			res,
			next,
			userModel,
			apiKeyModel,
			clientUserModel,
			Rollup5m,
			Rollup1h,
			Rollup1d,
		),
	);

	return router;
}
