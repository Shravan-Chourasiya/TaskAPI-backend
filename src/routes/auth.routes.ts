import express from "express";
import * as authControllers from "../modules/auth/controllers/auth.controller.js";
import {
	accessTokenHandler,
	refreshTokenHandler,
	strictAuthHandler,
} from "../middlewares/tokenhandler.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import {
	forgotPasswordUpdateSchema,
	loginDeleteRecoverAccSchema,
	otpResendSchema,
	otpSchema,
	// phoneGetNumberSchema,
	// phoneVerificationSchema,
	registerSchema,
	updateDetailsSchema,
	profileUpdateSchema,
} from "../libs/zod/auth.zodschema.js";
import {
	authRateLimiter,
	otpGenerationLimiter,
	otpVerificationLimiter,
	profileUpdateLimiter,
} from "../middlewares/ratelimiting.middleware.js";
import { fileUploadMiddleware } from "../middlewares/fileupload.middleware.js";

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

router.post("/logout", refreshTokenHandler, authControllers.logoutController);

router.patch(
	"/account/update",
	ZodValidatorMiddleware(updateDetailsSchema),
	accessTokenHandler,
	authControllers.updateDetailsController,
);

router.patch(
	"/profile/update",
	accessTokenHandler,
	fileUploadMiddleware,
	profileUpdateLimiter,
	ZodValidatorMiddleware(profileUpdateSchema),
	authControllers.updateProfile,
);

router.delete(
	"/account/delete",
	ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
	strictAuthHandler,
	authControllers.deleteAccountController,
);

router.patch(
	"/account/recover",
	ZodValidatorMiddleware(loginDeleteRecoverAccSchema),
	strictAuthHandler,
	authControllers.recoverDeletedAccountController,
);

router.get(
	"/account/info",
	accessTokenHandler,
	authControllers.getUserAccountController,
);

router.post(
	"/forgot-password/init",
	authControllers.forgotPasswordEmailController,
);

router.post("/forgot-password/update",
	ZodValidatorMiddleware(forgotPasswordUpdateSchema),
	authControllers.forgotPasswordUpdateController,
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

// router.post(
// 	"/phone/send-verification",
// 	ZodValidatorMiddleware(phoneGetNumberSchema),
// 	otpGenerationLimiter,
// 	authControllers.getPhoneNumberController,
// );

// router.post('/phone/verify',
// 	ZodValidatorMiddleware(phoneVerificationSchema),
// 	otpVerificationLimiter,
// 	authControllers.verifyPhoneController,
// );

export { router as authRouter };
