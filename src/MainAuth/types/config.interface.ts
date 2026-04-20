export interface Config {
	PORT: string;
	BASE_URL: string;
	MONGO_URI: string;
	DB_NAME: string;
	JWT_SECRET: string;
	JWT_SECRET_2: string;
	COOKIE_CONF_RT: object;
	COOKIE_CONF_AT: object;
	NODE_ENV: string;
	GMAIL_USER_EMAIL: string;
	GMAIL_REFRESH_TOKEN: string;
	GMAIL_CLIENT_ID: string;
	GMAIL_CLIENT_SECRET: string;
	OTP_SALT: string;
	API_BASE_URL: string;
	ALLOWED_ORIGINS: string[];
	
}
