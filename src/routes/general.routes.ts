import express from "express";
import { accessTokenHandlerFunction } from "../middlewares/tokenhandler.middleware.js";
import * as generalRouter from "../controllers/generalUse.controller.js";
import { apiRateLimiter } from "../middlewares/ratelimiting.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";

export function createGeneralRouter({
	userModel,
	sessionModel,
}: {
	userModel: any;
	sessionModel: any;
}): express.Router {
	const accessTokenHandler = createMiddlewareWrapper(
		sessionModel,
		accessTokenHandlerFunction,
		asyncErrorHandler,
	);
	const router = express.Router();

	router.get("/auth/me", apiRateLimiter, accessTokenHandler, (req, res, next) =>
		generalRouter.isUserController(req, res, next, userModel),
	);

	router.get("/health", (req, res, next) =>
		generalRouter.healthCheckController(req, res, next),
	);

	router.post("/contact", apiRateLimiter, (req, res, next) =>
		generalRouter.contactUsEmailController(req, res, next),
	);

	router.get("/auth/username/available", apiRateLimiter, (req, res, next) =>
		generalRouter.checkUsernameController(req, res, next, userModel),
	);

	return router;
}
