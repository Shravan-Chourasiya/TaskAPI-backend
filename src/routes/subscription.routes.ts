import express from 'express';
import * as subscriptionControllers from '../modules/auth/controllers/subscription.controller.js';
import { accessTokenHandler } from '../middlewares/tokenhandler.middleware.js';

const router = express.Router();

router.post('/buy-plan', accessTokenHandler, subscriptionControllers.buySubscriptionController);

export { router as subscriptionRouter };
