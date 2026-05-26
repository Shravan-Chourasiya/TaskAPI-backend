import express from 'express';
import * as subscriptionControllers from '../modules/auth/controllers/subscription.controller.js';
import { accessTokenHandler } from '../middlewares/tokenhandler.middleware.js';

const router = express.Router();

router.post('/create-order', accessTokenHandler, subscriptionControllers.buySubscriptionController);
router.post('/verify-payment', accessTokenHandler, subscriptionControllers.verifySubscriptionPayment);
router.post('/webhook', subscriptionControllers.razorpayWebhookHandler); // For auto-renewal


export { router as subscriptionRouter };
