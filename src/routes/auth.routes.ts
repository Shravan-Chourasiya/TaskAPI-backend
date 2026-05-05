import express from "express";
import * as authControllers from "../modules/auth/controllers/auth.controller.js";
import {
	accessTokenHandler,
	refreshTokenHandler,
} from "../middlewares/tokenhandler.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import {
	loginDeleteRecoverAccSchema,
	otpResendSchema,
	otpSchema,
	registerSchema,
	updateDetailsSchema,
} from "../libs/zodschemas.js";
import { authRateLimiter, otpGenerationLimiter, otpVerificationLimiter } from "../middlewares/ratelimiting.middleware.js";

const router = express.Router();

router.post(
	"/register",
	authRateLimiter,
	ZodValidatorMiddleware(registerSchema),
	authControllers.registerController,
);

router.post(
	"/verify",
	otpVerificationLimiter,
	ZodValidatorMiddleware(otpSchema),
	authControllers.verificationController,
);

router.post(
	"/login",
	authRateLimiter,
	ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
	authControllers.loginController,
);

router.delete("/logout", accessTokenHandler, authControllers.logoutController);

router.patch(
	"/account/update",
	ZodValidatorMiddleware(updateDetailsSchema),
	accessTokenHandler,
	authControllers.updateDetailsController,
);

router.delete(
	"/account/delete",
	ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
	accessTokenHandler,
	authControllers.deleteAccountController,
);

router.patch(
	"/account/recover",
	ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
	refreshTokenHandler,
	authControllers.recoverDeletedAccountController,
);

router.get(
	"/account/info",
	accessTokenHandler,
	authControllers.getUserAccountController,
);

router.post(
	"/token/refresh",
	refreshTokenHandler,
	authControllers.tokenRotationController,
);

router.post(
	"/resend-otp",
	ZodValidatorMiddleware(otpResendSchema),
	otpGenerationLimiter,
	authControllers.resendOtpController,
);

export { router as authRouter };
