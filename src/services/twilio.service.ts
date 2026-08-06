import { config } from "../configs/app.config.js";
import twilio from "twilio";
import { logger } from "../utils/logger.utils.js";

const accountSid = config.TWILIO_ACCOUNT_SID;
const authToken = config.TWILIO_AUTH_TOKEN;
const client = twilio(accountSid, authToken);

export async function sendVerificationSMS(to: string, otp: string) {
	const message = await client.messages.create({
		body: `Your verification OTP is: ${otp}`,
		from: config.TWILIO_PHONE_NUMBER,
		to: to,
	});

	logger.warn(message.body);
}

