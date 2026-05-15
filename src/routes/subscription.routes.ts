import express from 'express';
import * as subscriptionControllers from '../modules/auth/controllers/subscription.controller.js';
const router = express.Router();

router.post('/buy-plan',subscriptionControllers.buySubscriptionController)

export { router as subscriptionRouter };
