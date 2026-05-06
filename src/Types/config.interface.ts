export interface Config {
	PORT: string;
	BASE_URL: string;
	MONGO_URI: string;
	DB_NAME: string;
	REFRESH_TOKEN_JWT_SECRET: string;
	ACCESS_TOKEN_JWT_SECRET: string;
	REFRESH_TOKEN_COOKIE_CONFIG: object;
	ACCESS_TOKEN_COOKIE_CONFIG: object;
	NODE_ENV: string;
	GMAIL_USER_EMAIL: string;
	GMAIL_REFRESH_TOKEN: string;
	GMAIL_CLIENT_ID: string;
	GMAIL_CLIENT_SECRET: string;
	OTP_SALT: string;
	API_BASE_URL: string;
	ALLOWED_ORIGINS: string[];
	
}
