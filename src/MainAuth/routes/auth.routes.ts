import express from "express";
import * as authControllers from "../controllers/auth.controller.js";
import {
	accessTokenHandler,
	refreshTokenHandler,
} from "../middlewares/tokenHandler.middleware.js";
import { otpRateLimiter } from "../middlewares/rateLimiting.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodValidation.middleware.js";
import {
	loginDeleteRecoverAccSchema,
	otpSchema,
	registerSchema,
} from "../libs/auth.ZodSchema.js";

const router = express.Router();

router.post(
	"/register",
	ZodValidatorMiddleware(registerSchema),
	authControllers.registerController,
);

router.post(
	"/verify",
	ZodValidatorMiddleware(otpSchema),
	otpRateLimiter,
	authControllers.verificationController,
);

router.post(
	"/login",
	ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
	authControllers.loginController,
);

router.delete("/logout", accessTokenHandler, authControllers.logoutController);

router.patch(
	"/account/update",
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
	ZodValidatorMiddleware(otpSchema),
	otpRateLimiter,
	authControllers.resendOtpController
);

export { router as authRouter };
