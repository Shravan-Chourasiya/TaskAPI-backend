// services/razorpay.service.ts
import Razorpay from "razorpay";
import { config } from "../configs/app.config.js";
import crypto from "crypto";

export const razorpayInstance = new Razorpay({
	key_id: config.RAZORPAY_KEY_ID,
	key_secret: config.RAZORPAY_KEY_SECRET,
});

export async function createRazorpayOrder(
	amountRs: number,
	currency: string = "INR",
	receipt: string,
) {
	const options = {
		amount: amountRs * 100, // Convert to paise
		currency,
		receipt,
	};
	return await razorpayInstance.orders.create(options);
}

export function verifyRazorpaySignature(
	orderId: string,
	paymentId: string,
	signature: string,
): boolean {
	const text = `${orderId}|${paymentId}`;
	const generated = crypto
		.createHmac("sha256", config.RAZORPAY_KEY_SECRET)
		.update(text)
		.digest("hex");
	return generated === signature;
}
