import express from "express";
import * as authControllers from "../modules/auth/controllers/auth.controller.js";
import {
	accessTokenHandlerFunction,
	refreshTokenHandlerFunction,
	strictAuthHandlerFunction,
} from "../middlewares/tokenhandler.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import {
	loginDeleteRecoverAccSchema,
	otpResendSchema,
	otpSchema,
	registerSchema,
	updateDetailsSchema,
	profileUpdateSchema,
	twoFAVerifySchema,
	emailSchema,
	totpSchema,
} from "../libs/zod/auth.zodschema.js";
import {
	authRateLimiter,
	otpGenerationLimiter,
	otpVerificationLimiter,
	profileUpdateLimiter,
} from "../middlewares/ratelimiting.middleware.js";
import { fileUploadMiddleware } from "../middlewares/fileupload.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";

export function createAuthRouter({
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
	const refreshTokenHandler = createMiddlewareWrapper(
		sessionModel,
		refreshTokenHandlerFunction,
		asyncErrorHandler,
	);
	const strictAuthHandler = createMiddlewareWrapper(
		sessionModel,
		strictAuthHandlerFunction,
		asyncErrorHandler,
	);
	const router = express.Router();

	router.post(
		"/register",
		authRateLimiter,
		ZodValidatorMiddleware(registerSchema),
		(req, res, next) =>
			authControllers.registerController(req, res, next, userModel),
	);

	router.post(
		"/login",
		authRateLimiter,
		ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
		(req, res, next) =>
			authControllers.loginController(req, res, next, userModel, sessionModel),
	);

	router.post("/logout", refreshTokenHandler, (req, res, next) =>
		authControllers.logoutController(req, res, next, userModel, sessionModel),
	);

	router.post("/token/refresh", refreshTokenHandler, (req, res, next) =>
		authControllers.tokenRotationController(
			req,
			res,
			next,
			userModel,
			sessionModel,
		),
	);

	// ── OTP ────────────────────────────────────────────────────────────────────

	router.post(
		"/otp/verify",
		otpVerificationLimiter,
		ZodValidatorMiddleware(otpSchema),
		(req, res, next) =>
			authControllers.verificationController(
				req,
				res,
				next,
				userModel,
				sessionModel,
			),
	);

	router.post(
		"/otp/resend",
		ZodValidatorMiddleware(otpResendSchema),
		otpGenerationLimiter,
		(req, res, next) =>
			authControllers.resendOtpController(req, res, next, userModel),
	);

	// ── Password ───────────────────────────────────────────────────────────────

	router.post("/password/forgot", (req, res, next) =>
		authControllers.forgotPasswordEmailController(req, res, next, userModel),
	);

	// ── Account ────────────────────────────────────────────────────────────────

	router.get("/account", accessTokenHandler, (req, res, next) =>
		authControllers.getUserAccountController(req, res, next, userModel),
	);

	router.patch(
		"/account",
		ZodValidatorMiddleware(updateDetailsSchema),
		accessTokenHandler,
		(req, res, next) =>
			authControllers.updateDetailsController(req, res, next, userModel),
	);

	router.delete(
		"/account",
		ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
		strictAuthHandler,
		(req, res, next) =>
			authControllers.deleteAccountController(req, res, next, userModel),
	);

	router.patch(
		"/account/recover",
		ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
		strictAuthHandler,
		(req, res, next) =>
			authControllers.recoverDeletedAccountController(
				req,
				res,
				next,
				userModel,
				sessionModel,
			),
	);

	router.patch(
		"/account/profile",
		accessTokenHandler,
		fileUploadMiddleware,
		profileUpdateLimiter,
		ZodValidatorMiddleware(profileUpdateSchema),
		(req, res, next) =>
			authControllers.updateProfile(req, res, next, userModel),
	);

	router.post(
		"/account/2fa/enable",
		accessTokenHandler,
		(req: any, res, next) =>
			authControllers.enable2FAController(req, res, next, userModel),
	);
	router.post(
		"/account/2fa/confirm",
		accessTokenHandler,
		ZodValidatorMiddleware(totpSchema),
		(req: any, res, next) =>
			authControllers.confirm2FAController(req, res, next, userModel),
	);

	router.post(
		"/account/2fa/verify",
		ZodValidatorMiddleware(totpSchema),
		(req: any, res, next) =>
			authControllers.verify2FAController(
				req,
				res,
				next,
				userModel,
				sessionModel,
			),
	);
	router.post(
		"/account/2fa/disable",
		accessTokenHandler,
		ZodValidatorMiddleware(totpSchema),
		(req: any, res, next) =>
			authControllers.disable2FAController(req, res, next, userModel),
	);

	return router;
}
