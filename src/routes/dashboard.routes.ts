import express from "express";
import { ClientUserStaticMethods } from "../modules/clientauth/types/userMongo.type.js";
import { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import { IRollupBucket } from "../modules/metrics/types/rollupData.type.js";
import { UserStaticMethods } from "../types/mongoModels/user.type.js";
import { Model } from "mongoose";
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
	const router: express.Router = express.Router();

	const deps = { userModel, apiKeyModel, clientUserModel, Rollup5m, Rollup1h, Rollup1d };

	router.get("/api-keys", (req, res, next) =>
		dashboardControllers.getAllApiMetricsController(req, res, next, deps),
	);

	router.get("/api-keys/:keyId", (req, res, next) =>
		dashboardControllers.getSpecificApiMetricsController(req, res, next, deps),
	);

	return router;
}
