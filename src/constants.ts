// ============ RATE LIMITING ============
const contants = {
	AUTH_RATE_LIMIT_MAX: 10,
	OTP_RATE_LIMIT_MAX: 10,
	UPDATE_RATE_LIMIT_MAX: 5,
	APIKEY_CREATION_RATE_LIMIT_MAX: 20,
	GENERAL_APIKEY_RATE_LIMIT_MAX: 25,
	GENERAL_API_POINT_RATE_LIMIT_MAX: 100,
	GENERAL_API_POINT_RL_TIME_WINDOW_MS: 15 * 60 * 1000,
	OTP_RL_TIME_WINDOW_MS: 10 * 60 * 1000,
	AUTH_RL_TIME_WINDOW_MS: 10 * 60 * 1000,
	UPDATE_RL_TIME_WINDOW_MS: 2 * 60 * 1000,
	APIKEY_CREATION_RL_TIME_WINDOW_MS: 5 * 60 * 1000,
	GENERAL_APIKEY_RL_TIME_WINDOW_MS: 10 * 60 * 1000,
};

// ============ AUTHENTICATION & SECURITY ============
export const AUTH_CONSTANTS = {
	ACCESS_TOKEN_EXPIRY: '10m',
	REFRESH_TOKEN_EXPIRY: '7d',
	MAX_ACTIVE_SESSIONS: 5,
	FAILED_LOGIN_THRESHOLD_LOCK: 5,
	FAILED_LOGIN_THRESHOLD_TEMP_LOCK: 10,
	FAILED_LOGIN_THRESHOLD_PERM_LOCK: 15,
	BCRYPT_SALT_ROUNDS: 12,
	OTP_LENGTH: 6,
	OTP_EXPIRY_MINUTES: 10,
	SOFT_DELETE_GRACE_PERIOD_DAYS: 30,
} as const;

// ============ FILE UPLOAD ============
export const FILE_UPLOAD_CONSTANTS = {
	MAX_FILE_SIZE: 5 * 1024 * 1024,
	ALLOWED_MIMETYPES: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'],
	AVATAR_FIELD_NAME: 'avatar',
} as const;

// ============ SUBSCRIPTION ============
export const SUBSCRIPTION_PLANS = {
	Free: { price: 0 },
	Basic: { price: 5 },
	Pro: { price: 15 },
};

export const SUBSCRIPTION_CONSTANTS = {
	CURRENCY: 'INR',
	DAYS_PER_MONTH: 28,
	TRANSACTION_ID_PREFIX: 'TXN',
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
	SAME_SITE: 'strict' as const,
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
export const REDIS_PREFIXES = {
	RATE_LIMIT_API: 'rl:api:',
	RATE_LIMIT_AUTH: 'rl:auth:',
	RATE_LIMIT_OTP_GEN: 'rl:otp:gen:',
	RATE_LIMIT_OTP_VERIFY: 'rl:otp:verify:',
	RATE_LIMIT_UPDATE: 'rl:update:',
	RATE_LIMIT_GENERAL_API: 'rl:general:api:',
	OTP_STORAGE: 'otp:',
	SESSION: 'session:',
} as const;

// ============ EMAIL PURPOSES ============
export const EMAIL_PURPOSES = {
	VERIFICATION: 'verification',
	PASSWORD_RESET: 'password_reset',
	ACCOUNT_RECOVERY: 'account_recovery',
	EMAIL_CHANGE: 'email_change',
} as const;

export const EMAIL_PURPOSE_ABBR = {
	VERIFICATION: 'VER',
	PASSWORD_RESET: 'PWD',
	ACCOUNT_RECOVERY: 'REC',
	EMAIL_CHANGE: 'EMC',
} as const;

// ============ STATUS ENUMS ============
export const USER_STATUS = {
	ACTIVE: 'Active',
	LOCKED: 'Locked',
	TEMP_LOCKED: 'TempLocked',
	DELETED: 'Deleted',
} as const;

export const SESSION_STATUS = {
	ACTIVE: 'Active',
	REVOKED: 'Revoked',
	EXPIRED: 'Expired',
} as const;

export const SUBSCRIPTION_STATUS = {
	ACTIVE: 'Active',
	EXPIRED: 'Expired',
	CANCELLED: 'Cancelled',
	PENDING: 'Pending',
} as const;

export const PAYMENT_STATUS = {
	PENDING: 'Pending',
	COMPLETED: 'Completed',
	FAILED: 'Failed',
} as const;

export const PAYMENT_METHODS = {
	CARD: 'card',
	NETBANKING: 'netbanking',
	UPI: 'upi',
	WALLET: 'wallet',
} as const;

export default contants;
