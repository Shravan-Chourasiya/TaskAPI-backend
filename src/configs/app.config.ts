import "dotenv/config";
import type { Config } from "../Types/config.interface.js";
import {
	getCookieVar,
	getEnvVar,
	getEnvVarArr,
} from "../utils/configenv.utils.js";
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
	OTP_SALT: getEnvVar("OTP_SALT"),
	ACCESS_TOKEN_COOKIE_CONFIG: getCookieVar("ACCESS_TOKEN_COOKIE_CONFIG"),
	REFRESH_TOKEN_COOKIE_CONFIG: getCookieVar("REFRESH_TOKEN_COOKIE_CONFIG"),
	API_BASE_URL: getEnvVar("API_BASE_URL"),
	ALLOWED_ORIGINS: getEnvVarArr("ALLOWED_ORIGINS"),
};
