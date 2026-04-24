import express from "express";
import * as authControllers from "../modules/auth/controllers/auth.controller.js";
import {
	accessTokenHandler,
	refreshTokenHandler,
} from "../middlewares/tokenhandler.middleware.js";
import { otpRateLimiter } from "../middlewares/ratelimiting.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import {
	loginDeleteRecoverAccSchema,
	otpResendSchema,
	otpSchema,
	registerSchema,
	updateDetailsSchema,
} from "../libs/zodschemas.js";

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
	otpRateLimiter,
	authControllers.resendOtpController,
);

export { router as authRouter };
