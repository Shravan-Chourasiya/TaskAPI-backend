// ============ RATE LIMITING ============
const contants = {
	GENERAL_API_RL_TIME_WINDOW_MS: 15 * 60 * 1000,
	GENERAL_API_RATE_LIMIT_MAX: 100,

	AUTH_RL_TIME_WINDOW_MS: 10 * 60 * 1000,
	AUTH_RATE_LIMIT_MAX: 10,

	OTP_RL_TIME_WINDOW_MS: 10 * 60 * 1000,
	OTP_RATE_LIMIT_MAX: 5,

	PROFILE_UPDATE_RATE_LIMIT_MAX: 1,
	PROFILE_UPDATE_RL_TIME_WINDOW_MS: 2 * 60 * 1000,

	APIKEY_CREATION_RATE_LIMIT_MAX: 1,
	APIKEY_CREATION_RL_TIME_WINDOW_MS: 5 * 60 * 1000,

	GENERAL_APIKEY_RATE_LIMIT_MAX: 5,
	GENERAL_APIKEY_RL_TIME_WINDOW_MS: 10 * 60 * 1000,

	APIKEY_UPDATE_RATE_LIMIT_MAX: 5,
	APIKEY_UPDATE_RL_TIME_WINDOW_MS: 10 * 60 * 1000,

	APIKEY_USAGE_RATE_LIMIT_MAX: 50,
	APIKEY_USAGE_RL_TIME_WINDOW_MS: 10 * 60 * 1000,
};

// ============ AUTHENTICATION & SECURITY ============
export const AUTH_CONSTANTS = {
	ACCESS_TOKEN_EXPIRY: "10m",
	REFRESH_TOKEN_EXPIRY: "7d",
	MAX_ACTIVE_SESSIONS: 5,
	FAILED_LOGIN_THRESHOLD_LOCK: 5,
	FAILED_LOGIN_THRESHOLD_TEMP_LOCK: 8,
	FAILED_LOGIN_THRESHOLD_PERM_LOCK: 12,
	BCRYPT_SALT_ROUNDS: 12,
	OTP_LENGTH: 6,
	OTP_EXPIRY_MINUTES: 10,
	SOFT_DELETE_GRACE_PERIOD_DAYS: 30,
} as const;

// ============ FILE UPLOAD ============
export const FILE_UPLOAD_CONSTANTS = {
	MAX_FILE_SIZE: 5 * 1024 * 1024,
	ALLOWED_MIMETYPES: ["image/jpeg", "image/png", "image/jpg", "image/webp"],
	AVATAR_FIELD_NAME: "avatar",
} as const;

// ============ SUBSCRIPTION ============
export const SUBSCRIPTION_PLANS = {
	Free: { price: 0 },
	Basic: { price: 5 },
	Pro: { price: 15 },
};

export const SUBSCRIPTION_CONSTANTS = {
	CURRENCY: "INR",
	DAYS_PER_MONTH: 28,
	TRANSACTION_ID_PREFIX: "TXN",
	TRANSACTION_ID_BYTES: 8,
} as const;

export const getPlanPrice = (
	planName: keyof typeof SUBSCRIPTION_PLANS,
): number => {
	return SUBSCRIPTION_PLANS[planName]?.price ?? 0;
};

// ============ COOKIE SETTINGS ============
export const COOKIE_CONSTANTS = {
	HTTP_ONLY: true,
	SECURE: true,
	SAME_SITE: "strict" as const,
	ACCESS_TOKEN_MAX_AGE: 10 * 60 * 1000,
	REFRESH_TOKEN_MAX_AGE: 7 * 24 * 60 * 60 * 1000,
} as const;

// ============ USER SCHEMA LIMITS ============
export const USER_LIMITS = {
	USERNAME_MIN_LENGTH: 3,
	USERNAME_MAX_LENGTH: 40,
	PASSWORD_MIN_LENGTH: 8,
	BIO_MAX_LENGTH: 500,
	NAME_MAX_LENGTH: 50,
} as const;

// ============ REDIS PREFIXES ============
export const APP_REDIS_PREFIXES = {
	RATE_LIMIT_GENERAL_API: "rl:general:api:",
	RATE_LIMIT_AUTH: "rl:auth:",
	RATE_LIMIT_OTP_GENERATION: "rl:otp:generation:",
	RATE_LIMIT_OTP_VERIFICATION: "rl:otp:verification:",
	RATE_LIMIT_PROFILE_UPDATE: "rl:profile:update:",
	RATE_LIMIT_GENERAL_APIKEY: "rl:apikey:general:",
	RATE_LIMIT_APIKEY_CREATION: "rl:apikey:creation:",
	RATE_LIMIT_APIKEY_UPDATE: "rl:apikey:update:",
	RATE_LIMIT_APIKEY_USAGE: "rl:apikey:usage:",
	OTP_STORAGE: "otp:",
	SESSION: "session:",
} as const;

export const CLIENT_REDIS_PREFIXES = {
	RATE_LIMIT_GENERAL_API: "rl:client:general:api:",
	RATE_LIMIT_AUTH: "rl:client:auth:",
	RATE_LIMIT_OTP_GENERATION: "rl:client:otp:generation:",
	RATE_LIMIT_OTP_VERIFICATION: "rl:client:otp:verification:",
	RATE_LIMIT_PROFILE_UPDATE: "rl:client:profile:update:",
	OTP_STORAGE: "client:otp:",
	SESSION: "client:session:",
} as const;

export default contants;
