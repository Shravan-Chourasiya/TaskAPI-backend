import express from "express";
import { accessTokenHandler } from "../middlewares/tokenhandler.middleware.js";
import * as generalRouter from "../controllers/generalUse.controller.js";

const router = express.Router();

router.get("/is-user",accessTokenHandler,generalRouter.isUserController);

router.get('/health',generalRouter.healthCheckController);


export { router as generalRouter };