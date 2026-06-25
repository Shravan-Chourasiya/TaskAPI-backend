import express from "express";
import * as subscriptionControllers from "../modules/auth/controllers/subscription.controller.js";
import { accessTokenHandlerFunction } from "../middlewares/tokenhandler.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";

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

	router.post("/create-order", accessTokenHandler, (req, res, next) =>
		subscriptionControllers.buySubscriptionController(
			req,
			res,
			next,
			userModel,
			subscriptionModel,
		),
	);
	router.post("/verify-payment", accessTokenHandler, (req, res, next) =>
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
