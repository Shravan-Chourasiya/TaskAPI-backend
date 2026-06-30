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
	ResendOTPSchema,
	ForgotPasswordSchema,
	UpdatePasswordSchema,
	UpdateUsernameSchema,
	UpdateEmailSchema,
	DeleteAccountSchema,
	RecoverAccountSchema,
	VerifyEmailOnRegisterSchema,
	VerifyNewEmailSchema,
	VerifyForgotPasswordSchema,
	VerifyUpdatePasswordSchema,
	VerifyAccountRecoverySchema,
} from "../modules/clientauth/utils/zodSchemas.js";
import type { ClientUserStaticMethods } from "../modules/clientauth/types/userMongo.type.js";
import type { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import { CLIENT_OTP_PURPOSES } from "../constants.js";

export function createClientUserRouter({
	userModel,
	apiKeyModel,
}: {
	userModel: ClientUserStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
}): express.Router {

	const apikeyHandler = createMiddlewareWrapper(
		apiKeyModel,
		apikeyHandlerFunction,
		asyncErrorHandler,
	);

	const router = express.Router();

	// All client routes are protected by API key + general rate limiter
	router.use(apikeyHandler, clientApiRateLimiter);

	// ─── Auth ──────────────────────────────────────────────────────────────────

	router.post(
		"/register",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(RegisterSchema),
		(req, res, next) =>
			clientUserControllers.registerController(req, res, next, userModel),
	);

	router.post(
		"/login",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(LoginSchema),
		(req, res, next) =>
			clientUserControllers.loginController(req, res, next, userModel),
	);

	router.post(
		"/logout",
		(req, res, next) =>
			clientUserControllers.logoutController(req, res, next, userModel),
	);

	// ─── OTP ───────────────────────────────────────────────────────────────────
	// Unified verify endpoint — ?purpose= one of CLIENT_OTP_PURPOSES values
	// Each purpose requires a different body shape — see controller for details

	// ve-em-or
	router.post(
		"/verify",
		clientOtpVerificationLimiter,
		(req, res, next) => {
			const purpose = req.query.purpose as string;
			const schemaMap: Record<string, Parameters<typeof ZodValidatorMiddleware>[0]> = {
				[CLIENT_OTP_PURPOSES.VERIFY_EMAIL_REGISTER]: VerifyEmailOnRegisterSchema,
				[CLIENT_OTP_PURPOSES.VERIFY_NEW_EMAIL]:      VerifyNewEmailSchema,
				[CLIENT_OTP_PURPOSES.FORGOT_PASSWORD]:       VerifyForgotPasswordSchema,
				[CLIENT_OTP_PURPOSES.UPDATE_PASSWORD]:       VerifyUpdatePasswordSchema,
				[CLIENT_OTP_PURPOSES.ACCOUNT_RECOVERY]:      VerifyAccountRecoverySchema,
			};
			const schema = schemaMap[purpose];
			if (schema) {
				return ZodValidatorMiddleware(schema)(req, res, next);
			}
			next(); // unknown purpose handled inside controller
		},
		(req, res, next) =>
			clientUserControllers.verifyOTPController(req, res, next, userModel),
	);

	router.post(
		"/resend-otp",
		clientOtpGenerationLimiter,
		ZodValidatorMiddleware(ResendOTPSchema),
		(req, res, next) =>
			clientUserControllers.resendOTPController(req, res, next, userModel),
	);

	// ─── Password ──────────────────────────────────────────────────────────────

	// Forgot password (unauthenticated) — sends OTP, complete via /verify?purpose=fr-pa
	router.post(
		"/forgot-password",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(ForgotPasswordSchema),
		(req, res, next) =>
			clientUserControllers.initiateForgotPasswordController(req, res, next, userModel),
	);

	// Authenticated password update — verifies current password, sends OTP, complete via /verify?purpose=up-pa
	router.post(
		"/account/password/initiate",
		ZodValidatorMiddleware(UpdatePasswordSchema),
		(req, res, next) =>
			clientUserControllers.initiateUpdatePasswordController(req, res, next, userModel),
	);

	// ─── Account ───────────────────────────────────────────────────────────────

	router.patch(
		"/account/username",
		clientProfileUpdateLimiter,
		ZodValidatorMiddleware(UpdateUsernameSchema),
		(req, res, next) =>
			clientUserControllers.updateUsernameController(req, res, next, userModel),
	);

	// Step 1: confirm password + check new email, send OTP to current email
	// Step 2: /verify?purpose=ve-em-cu (confirm current email, then sends OTP to new email)
	// Step 3: /verify?purpose=ve-em-up (confirm new email, commits change)
	router.post(
		"/account/email/initiate",
		clientProfileUpdateLimiter,
		ZodValidatorMiddleware(UpdateEmailSchema),
		(req, res, next) =>
			clientUserControllers.initiateEmailUpdateController(req, res, next, userModel),
	);

	router.delete(
		"/account/delete",
		ZodValidatorMiddleware(DeleteAccountSchema),
		(req, res, next) =>
			clientUserControllers.deleteAccountController(req, res, next, userModel),
	);

	// Recover soft-deleted account — sends OTP, complete via /verify?purpose=ac-re
	router.post(
		"/account/recover",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(RecoverAccountSchema),
		(req, res, next) =>
			clientUserControllers.recoverAccountController(req, res, next, userModel),
	);

	return router;
}
