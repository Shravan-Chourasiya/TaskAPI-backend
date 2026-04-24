import nodemailer from "nodemailer";
import { config } from "../configs/configs.js";
import type { NodemailerError } from "../modules/auth/types/nodemailer.interface.js";

const transporter = nodemailer.createTransport({
	service: "gmail",
	auth: {
		type: "OAuth2",
		user: config.GMAIL_USER_EMAIL,
		clientId: config.GMAIL_CLIENT_ID,
		clientSecret: config.GMAIL_CLIENT_SECRET,
		refreshToken: config.GMAIL_REFRESH_TOKEN,
	},
});

export async function sendVerificationEmail(
	from: string,
	to: string,
	subject: string,
	html: string,
) {
	try {
		const info = await transporter.sendMail({
			from: from,
			to: to,
			subject: subject,
			html: html,
		});
		console.log("Email sent successfully:", info.messageId);
		if (info.response) {
			return info.messageId;
		}
		throw new Error("Failed to send email - no response from server");
	} catch (err) {
		const error = err as NodemailerError;

		switch (error.code) {
			case "ECONNECTION":
			case "ETIMEDOUT":
				console.error("Network error - retry later:", error.message);
				throw new Error("Network error - please try again later");
				break;

			case "EAUTH":
				console.error("Authentication failed:", error.message);
				throw new Error("Authentication failed - please check credentials");
				break;

			case "EENVELOPE":
				console.error("Invalid recipients:", error.rejected);
				throw new Error("Invalid recipient email address");
				break;

			default:
				console.error("Send failed:", error.message, error);
				throw new Error("Failed to send email - please try again");
		}
	}
}
