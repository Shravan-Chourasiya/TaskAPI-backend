import express from "express";
import * as clientUserControllers from "../modules/clientauth/controllers/clientUser.controller.js";
import { apikeyHandlerFunction } from "../middlewares/apikeyhandler.middleware.js";
import { resolveIP } from "../middlewares/ipResolver.middleware.js";
import { resolveScopes } from "../middlewares/scopeResolver.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import { createPurposeValidatorMiddleware } from "../middlewares/purposevalidator.middleware.js";
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

const VALID_PURPOSES = Object.values(CLIENT_OTP_PURPOSES) as string[];

const verifyPurposeSchemaMap: Record<string, Parameters<typeof ZodValidatorMiddleware>[0]> = {
	[CLIENT_OTP_PURPOSES.VERIFY_EMAIL_REGISTER]: VerifyEmailOnRegisterSchema,
	[CLIENT_OTP_PURPOSES.VERIFY_NEW_EMAIL]:      VerifyNewEmailSchema,
	[CLIENT_OTP_PURPOSES.FORGOT_PASSWORD]:       VerifyForgotPasswordSchema,
	[CLIENT_OTP_PURPOSES.UPDATE_PASSWORD]:       VerifyUpdatePasswordSchema,
	[CLIENT_OTP_PURPOSES.ACCOUNT_RECOVERY]:      VerifyAccountRecoverySchema,
};

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

	const ipResolver = createMiddlewareWrapper(
		apiKeyModel,
		resolveIP,
		asyncErrorHandler,
	);

	const scopeResolver = createMiddlewareWrapper(
		apiKeyModel,
		resolveScopes,
		asyncErrorHandler,
	);

	const router = express.Router();
	router.use(apikeyHandler, ipResolver, scopeResolver, clientApiRateLimiter);

	// ── Auth ───────────────────────────────────────────────────────────────────

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

	router.post("/logout", (req, res, next) =>
		clientUserControllers.logoutController(req, res, next, userModel),
	);

	// ── OTP ────────────────────────────────────────────────────────────────────

	router.post(
		"/otp/verify",
		clientOtpVerificationLimiter,
		createPurposeValidatorMiddleware(verifyPurposeSchemaMap, VALID_PURPOSES),
		(req, res, next) =>
			clientUserControllers.verifyOTPController(req, res, next, userModel),
	);

	router.post(
		"/otp/resend",
		clientOtpGenerationLimiter,
		ZodValidatorMiddleware(ResendOTPSchema),
		(req, res, next) =>
			clientUserControllers.resendOTPController(req, res, next, userModel),
	);

	// ── Password ───────────────────────────────────────────────────────────────

	router.post(
		"/password/forgot",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(ForgotPasswordSchema),
		(req, res, next) =>
			clientUserControllers.initiateForgotPasswordController(req, res, next, userModel),
	);

	router.post(
		"/account/password",
		ZodValidatorMiddleware(UpdatePasswordSchema),
		(req, res, next) =>
			clientUserControllers.initiateUpdatePasswordController(req, res, next, userModel),
	);

	// ── Account ────────────────────────────────────────────────────────────────

	router.patch(
		"/account/username",
		clientProfileUpdateLimiter,
		ZodValidatorMiddleware(UpdateUsernameSchema),
		(req, res, next) =>
			clientUserControllers.updateUsernameController(req, res, next, userModel),
	);

	router.post(
		"/account/email",
		clientProfileUpdateLimiter,
		ZodValidatorMiddleware(UpdateEmailSchema),
		(req, res, next) =>
			clientUserControllers.initiateEmailUpdateController(req, res, next, userModel),
	);

	router.delete(
		"/account",
		ZodValidatorMiddleware(DeleteAccountSchema),
		(req, res, next) =>
			clientUserControllers.deleteAccountController(req, res, next, userModel),
	);

	router.post(
		"/account/recover",
		clientAuthRateLimiter,
		ZodValidatorMiddleware(RecoverAccountSchema),
		(req, res, next) =>
			clientUserControllers.recoverAccountController(req, res, next, userModel),
	);

	return router;
}
