import nodemailer from "nodemailer";
import { config } from "../configs/configs.js";
import type { NodemailerError } from "../types/nodemailer.interface.js";

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
		return info.messageId;
	} catch (err) {
		const error = err as NodemailerError;

		switch (error.code) {
			case "ECONNECTION":
			case "ETIMEDOUT":
				console.error("Network error - retry later:", error.message);
				break;

			case "EAUTH":
				console.error("Authentication failed:", error.message);
				break;

			case "EENVELOPE":
				console.error("Invalid recipients:", error.rejected);
				break;

			default:
				console.error("Send failed:", error.message, error);
		}
	}
}
