import "dotenv/config";
import type { Config } from "../types/config.interface.js";
import { getEnvVar, getEnvVarArr } from "../utils/configenv.utils.js";
export const config: Config = {
	PORT: getEnvVar("PORT"),
	BASE_URL: getEnvVar("BASE_URL"),
	MONGO_URI: getEnvVar("MONGO_URI"),
	DB_NAME: getEnvVar("DB_NAME"),
	REFRESH_TOKEN_JWT_SECRET: getEnvVar("REFRESH_TOKEN_JWT_SECRET"),
	ACCESS_TOKEN_JWT_SECRET: getEnvVar("ACCESS_TOKEN_JWT_SECRET"),
	NODE_ENV: getEnvVar("NODE_ENV"),
	GMAIL_USER_EMAIL: getEnvVar("GMAIL_USER_EMAIL"),
	GMAIL_REFRESH_TOKEN: getEnvVar("GMAIL_REFRESH_TOKEN"),
	GMAIL_CLIENT_ID: getEnvVar("GMAIL_CLIENT_ID"),
	GMAIL_CLIENT_SECRET: getEnvVar("GMAIL_CLIENT_SECRET"),
	TWILIO_ACCOUNT_SID: getEnvVar("TWILIO_ACCOUNT_SID"),
	TWILIO_AUTH_TOKEN: getEnvVar("TWILIO_AUTH_TOKEN"),
	TWILIO_PHONE_NUMBER: getEnvVar("TWILIO_PHONE_NUMBER"),
	OTP_SALT: getEnvVar("OTP_SALT"),
	API_BASE_URL: getEnvVar("API_BASE_URL"),
	ALLOWED_ORIGINS: getEnvVarArr("ALLOWED_ORIGINS"),
	CLOUDINARY_URL: getEnvVar("CLOUDINARY_URL")
};
