import express from "express";
import * as subscriptionControllers from "../modules/auth/controllers/subscription.controller.js";
import { accessTokenHandlerFunction } from "../middlewares/tokenhandler.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import { buySubscriptionSchema } from "../libs/zod/subscription.zodschema.js";

export function createSubscriptionRouter({
	userModel,
	subscriptionModel,
	sessionModel,
}: {
	userModel: any;
	subscriptionModel: any;
	sessionModel: any;
}): express.Router {
	const accessTokenHandler = createMiddlewareWrapper(
		sessionModel,
		accessTokenHandlerFunction,
		asyncErrorHandler,
	);
	const router = express.Router();

	router.post("/order", accessTokenHandler, ZodValidatorMiddleware(buySubscriptionSchema), (req, res, next) =>
		subscriptionControllers.buySubscriptionController(
			req,
			res,
			next,
			userModel,
			subscriptionModel,
		),
	);
	router.post("/order/verify", accessTokenHandler, (req, res, next) =>
		subscriptionControllers.verifySubscriptionPayment(
			req,
			res,
			next,
			userModel,
			subscriptionModel,
		),
	);
	router.post("/webhook", subscriptionControllers.razorpayWebhookHandler); // For auto-renewal

	return router;
}
