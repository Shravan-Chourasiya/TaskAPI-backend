import nodemailer from "nodemailer";
import { config } from "../configs/app.config.js";
import { handleNodemailerError } from "../utils/nodemailer.utils.js";

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
		if (info.response) {
			return info.messageId;
		}
		throw new Error("Failed to send email - no response from server");
	} catch (err: any) {
		handleNodemailerError(err);
	}
}

export async function sendContactUsEmail(
	from: string,
	to: string,
	name: string,
	html: string,
) {
	try {
		const subject: string = `New Contact Us Message from user ${name}`;
		const info = await transporter.sendMail({
			from: from,
			to: to,
			subject: subject,
			html: html,
		});
		if (info.response) {
			return info.messageId;
		}
		throw new Error("Failed to send email - no response from server");
	} catch (err: any) {
		handleNodemailerError(err);
	}
}
