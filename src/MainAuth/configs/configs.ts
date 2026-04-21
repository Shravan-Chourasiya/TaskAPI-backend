import "dotenv/config";
import type { Config } from "../types/config.interface.js";
import { getCookieVar, getEnvVar, getEnvVarArr } from "../utils/config.env.utils.js";
export const config:Config = {
    PORT:getEnvVar("PORT"),
    BASE_URL:getEnvVar("BASE_URL"),
    MONGO_URI:getEnvVar("MONGO_URI"),
    DB_NAME:getEnvVar("DB_NAME"),
    JWT_SECRET:getEnvVar("JWT_SECRET"),
    JWT_SECRET_2:getEnvVar("JWT_SECRET_2"),
    NODE_ENV:getEnvVar("NODE_ENV"),
    GMAIL_USER_EMAIL:getEnvVar("GMAIL_USER_EMAIL"),
    GMAIL_REFRESH_TOKEN:getEnvVar("GMAIL_REFRESH_TOKEN"),
    GMAIL_CLIENT_ID:getEnvVar("GMAIL_CLIENT_ID"),
    GMAIL_CLIENT_SECRET:getEnvVar("GMAIL_CLIENT_SECRET"),
    OTP_SALT:getEnvVar("OTP_SALT"),
    COOKIE_CONF_AT:getCookieVar("COOKIE_CONF_AT"),
    COOKIE_CONF_RT:getCookieVar("COOKIE_CONF_RT"),
    COOKIE_CONF_TT:getCookieVar("COOKIE_CONF_TT"),
    API_BASE_URL:getEnvVar("API_BASE_URL"),
    ALLOWED_ORIGINS:getEnvVarArr("ALLOWED_ORIGINS")
}
