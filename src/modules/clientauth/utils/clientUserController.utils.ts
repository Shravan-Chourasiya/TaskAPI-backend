import { CLIENT_REDIS_PREFIXES, CLIENT_OTP_TTL_SECONDS } from "../../../constants.js";
import { config } from "../../../configs/app.config.js";
import { sendVerificationEmail } from "../../../services/nodemailer.service.js";
import { otpService } from "../../../services/redisotp.service.js";
import { generateOTP, getOtpHTML } from "../../../utils/nodemailer.utils.js";
import { emailPurposeMapper } from "../../auth/utils/authcontroller.utils.js";

export const OTP_PREFIX = CLIENT_REDIS_PREFIXES.OTP_STORAGE;

// ─── Send OTP email + store in Redis ─────────────────────────────────────────
// htmlTemplate: key passed to getOtpHTML (e.g. "verifyEmailOR", "resetPassword")
// purpose:      Redis key segment, must match what verifyOTP is called with
// docId:        stored as userId in Redis so verify controller can retrieve the user
// newValue:     optional, e.g. new email for ve-em-up flow

export async function sendAndStoreOTP(
	email: string,
	purpose: string,
	docId: string,
	htmlTemplate: string,
	newValue?: string,
): Promise<{ success: boolean; message?: string }> {
	const otp = generateOTP();
	const html = getOtpHTML(otp, htmlTemplate);
	const subject = emailPurposeMapper(purpose);

	const mailSent = await sendVerificationEmail(
		config.GMAIL_USER_EMAIL,
		email,
		subject,
		html,
	);
	if (!mailSent) {
		return { success: false, message: "Failed to send email. Please try again later." };
	}

	const stored = await otpService.storeOTP(
		email,
		otp,
		purpose,
		docId,
		newValue,
		CLIENT_OTP_TTL_SECONDS,
		OTP_PREFIX,
	);
	return stored;
}
