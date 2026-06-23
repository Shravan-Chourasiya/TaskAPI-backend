export interface Config {
	PORT: string;
	BASE_URL: string;
	MONGO_URI: string;
	DB_NAME: string;
	POSTGRES_DB_URI: string;
	REFRESH_TOKEN_JWT_SECRET: string;
	ACCESS_TOKEN_JWT_SECRET: string;
	NODE_ENV: string;
	GMAIL_USER_EMAIL: string;
	GMAIL_REFRESH_TOKEN: string;
	GMAIL_CLIENT_ID: string;
	GMAIL_CLIENT_SECRET: string;
	TWILIO_ACCOUNT_SID: string;
	TWILIO_AUTH_TOKEN: string;
	TWILIO_PHONE_NUMBER: string;
	OTP_SALT: string;
	API_BASE_URL: string;
	ALLOWED_ORIGINS: string[];
	CLOUDINARY_URL: string;
	RAZORPAY_KEY_ID: string;
	RAZORPAY_KEY_SECRET: string;
}
