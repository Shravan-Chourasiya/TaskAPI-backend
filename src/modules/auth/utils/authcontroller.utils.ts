import { config } from "../../../configs/app.config.js";
import { sendVerificationEmail } from "../../../services/nodemailer.service.js";
import { otpService } from "../../../services/redisotp.service.js";
import { generateOTP, getOtpHTML } from "../../../utils/nodemailer.utils.js";

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

	return otpService.storeOTP(email, otp, purpose, docId, newValue);
}

export const emailPurposeMapper = (purpose: string): string => {
	switch (purpose) {
		case "verifyEmailOR":
		case "ve-em-or":
			return "Email Verification for New Registration on TaskAPI";
		case "verifyEmailUP":
		case "ve-em-up":
			return "Email Verification for Email Update on TaskAPI";
		case "ve-em-cu":
			return "Confirm Your Current Email - TaskAPI";
		case "resetPassword":
		case "fr-pa":
			return "Password Reset Verification for Your TaskAPI Account";
		case "up-pa":
			return "Confirm Password Change - TaskAPI";
		case "accountRecovery":
		case "ac-re":
			return "Account Recovery Verification for Your TaskAPI Account";
		case "resendOtp":
			return "OTP Verification for Your TaskAPI Account";
		case "forgotPassword":
			return "Password Reset Verification for Your TaskAPI Account";
		case "deleteAccount":
			return "Account Deletion Scheduled for Your TaskAPI Account";
		default:
			return "Email Verification";
	}
};
