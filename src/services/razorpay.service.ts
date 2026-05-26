// services/razorpay.service.ts
import Razorpay from "razorpay";
import { config } from "../configs/app.config.js";
import crypto from "crypto";

export const razorpayInstance = new Razorpay({
	key_id: config.RAZORPAY_KEY_ID,
	key_secret: config.RAZORPAY_KEY_SECRET,
});

export async function createRazorpayOrder(
	amount: number,
	currency: string = "INR",
    receipt: string
) {
	return await razorpayInstance.orders.create({
		amount: amount * 100, // Convert to paise
		currency,
		receipt,
	});
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
