import express from "express";
import { accessTokenHandler } from "../middlewares/tokenhandler.middleware.js";
import * as generalRouter from "../controllers/generalUse.controller.js";
import { apiRateLimiter } from "../middlewares/ratelimiting.middleware.js";
import { ZodValidatorMiddleware } from "../middlewares/zodvalidation.middleware.js";
import { usernameSchema } from "../libs/zod/auth.zodschema.js";

const router = express.Router();

router.get("/is-user",apiRateLimiter, accessTokenHandler, generalRouter.isUserController);

router.get("/health", generalRouter.healthCheckController);

router.post("/contact-us", apiRateLimiter, generalRouter.contactUsEmailController);

router.get("/check-username", apiRateLimiter, generalRouter.checkUsernameController);


export { router as generalRouter };
