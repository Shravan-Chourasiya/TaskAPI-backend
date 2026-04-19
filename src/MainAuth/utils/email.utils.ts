import { config } from "../configs/configs.js";
import crypto from "crypto";

export function generateOTP() {
    return crypto.randomInt(100000,999999).toString();
}

export function getOtpHTML(otp:string, purpose:string) {
    let purposeDescription, actionText, purposeAbb;
    switch (purpose) {
        case "verifyEmailOR":
            purposeDescription = "verify your email address.";
            actionText = "Verify Email";
            purposeAbb = "ve-em-or";
            break;
        case "verifyEmailUP":
            purposeDescription = "verify your email address and update it .";
            actionText = "Verify Email";
            purposeAbb = "ve-em-up";
            break;
        case "resetPassword":
            purposeDescription = "reset your password.";
            actionText = "Reset Password";
            purposeAbb = "re-pa";
            break;
        case "account_recovery":
            purposeDescription = "recover your account.";
            actionText = "Recover Account";
            purposeAbb = "ac-re";
            break;
    }

    return `
    <div style="max-width: 400px; margin:auto; border: 1px solid #ddd; padding: 20px; font-family: sans-serif; line-height: 1.5;">
        <h2 style="text-align: center; color: #333;">Your OTP Code</h2>
        <p style="text-align: center; font-size: 24px; letter-spacing: 4px; margin: 30px 0; color: #555;"><strong>${otp}</strong></p>
        <p style="text-align: center; color: #777;">This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
        <p style="text-align: center; color: #777;">Click the link below to ${purposeDescription}</p>

        <a href="${config.BASE_URL}/verify?purpose=${purposeAbb}" target="_blank">
            <button style="display: block; margin: 20px auto; padding: 10px 20px; background-color: #007BFF; color: white; border: none; border-radius: 5px; text-decoration: none;">${actionText}</button>
        </a>
        <p style="text-align: center; color: #777;">If you did not request this code, please ignore this email.</p>
    </div>
    `
}
