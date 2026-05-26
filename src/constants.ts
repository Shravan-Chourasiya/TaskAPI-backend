const contants = {
	AUTH_RATE_LIMIT_MAX: 10, // Max attempts per 10 min for auth routes
	OTP_RATE_LIMIT_MAX: 10, // Max OTP requests per 10 min
	UPDATE_RATE_LIMIT_MAX: 5, // Max profile update requests per 10 min
	GENERAL_API_RATE_LIMIT_MAX: 100, // Max requests per 15 min for general API
	GENERAL_RL_TIME_WINDOW_MS: 15 * 60 * 1000, // 15 minutes in milliseconds,
	OTP_RL_TIME_WINDOW_MS: 10 * 60 * 1000, // 10 minutes in milliseconds,
	AUTH_RL_TIME_WINDOW_MS: 10 * 60 * 1000, // 10 minutes in milliseconds,
	UPDATE_RL_TIME_WINDOW_MS: 2 * 60 * 1000, // 2 minutes in milliseconds,
};
export const SUBSCRIPTION_PLANS = {
	Free: { price: 0 },
	Basic: { price: 5 },
	Pro: { price: 10 },
};

export const getPlanPrice = (
	planName: keyof typeof SUBSCRIPTION_PLANS,
): number => {
	return SUBSCRIPTION_PLANS[planName]?.price ?? 0;
};

export default contants;
