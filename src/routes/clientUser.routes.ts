import express from "express";
import * as clientUserControllers from "../modules/clientauth/controllers/clientUser.controller.js";
import { apikeyHandlerFunction } from "../middlewares/apikeyhandler.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";
import {
	clientApiRateLimiter,
	clientAuthRateLimiter,
	clientOtpGenerationLimiter,
	clientOtpVerificationLimiter,
	clientProfileUpdateLimiter,
} from "../modules/clientauth/utils/rateLimiters.js";
import {
	RegisterSchema,
	LoginSchema,
	VerifyOTPSchema,
	ResendOTPSchema,
	ForgotPasswordSchema,
	UpdatePasswordSchema,
	UpdateUsernameSchema,
	UpdateEmailSchema,
	DeleteAccountSchema,
} from "../modules/clientauth/utils/zodSchemas.js";
import type { ClientUsersStoreStaticMethods } from "../modules/clientauth/types/userMongo.type.js";
import { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";

export function createClientUserRouter({
	storeModel,
	apiKeyModel,
}: {
	storeModel: ClientUsersStoreStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
}): express.Router {

	// Inject apiKeyModel into apikeyHandlerFunction
	const apikeyHandler = createMiddlewareWrapper(
		apiKeyModel,
		apikeyHandlerFunction,
		asyncErrorHandler,
	);

	const router = express.Router();

	// All client routes are protected by apikey + general rate limiter
	router.use(apikeyHandler, clientApiRateLimiter);

	// ─── Auth ──────────────────────────────────────────────────────────────────

	router.post(
		"/register",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(RegisterSchema),
		(req, res, next) =>
			clientUserControllers.registerController(req, res, next, storeModel),
	);

	router.post(
		"/login",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(LoginSchema),
		(req, res, next) =>
			clientUserControllers.loginController(req, res, next, storeModel),
	);

	// ─── OTP ───────────────────────────────────────────────────────────────────

	// Centralised OTP verification — ?purpose=ve-em-or | ve-em-up | fr-pa | ac-re
	router.post(
		"/verify",
		clientOtpVerificationLimiter,
		ZodValidatorMiddleware(VerifyOTPSchema),
		(req, res, next) =>
			clientUserControllers.verificationController(req, res, next, storeModel),
	);

	router.post(
		"/resend-otp",
		clientOtpGenerationLimiter,
		ZodValidatorMiddleware(ResendOTPSchema),
		(req, res, next) =>
			clientUserControllers.resendOTPController(req, res, next, storeModel),
	);

	// ─── Password ──────────────────────────────────────────────────────────────

	// Step 1: send OTP to email
	router.post(
		"/forgot-password",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(ForgotPasswordSchema),
		(req, res, next) =>
			clientUserControllers.forgotPasswordController(req, res, next, storeModel),
	);

	// Step 2: done via /verify?purpose=fr-pa (verifies OTP + resets password in one call)

	// Authenticated password update (old + new password, no OTP)
	router.patch(
		"/account/password",
		ZodValidatorMiddleware(UpdatePasswordSchema),
		(req, res, next) =>
			clientUserControllers.updatePasswordController(req, res, next, storeModel),
	);

	// ─── Account ───────────────────────────────────────────────────────────────

	router.patch(
		"/account/username",
		clientProfileUpdateLimiter,
		ZodValidatorMiddleware(UpdateUsernameSchema),
		(req, res, next) =>
			clientUserControllers.updateUsernameController(req, res, next, storeModel),
	);

	// Step 1: send OTP to new email
	router.patch(
		"/account/email",
		clientProfileUpdateLimiter,
		ZodValidatorMiddleware(UpdateEmailSchema),
		(req, res, next) =>
			clientUserControllers.updateEmailController(req, res, next, storeModel),
	);

	// Step 2: done via /verify?purpose=ve-em-up

	router.delete(
		"/account/delete",
		ZodValidatorMiddleware(DeleteAccountSchema),
		(req, res, next) =>
			clientUserControllers.deleteAccountController(req, res, next, storeModel),
	);

	// Step 1: send OTP for recovery
	router.post(
		"/account/recover",
		clientAuthRateLimiter,
		(req, res, next) =>
			clientUserControllers.recoverAccountController(req, res, next, storeModel),
	);

	// Step 2: done via /verify?purpose=ac-re

	return router;
}
