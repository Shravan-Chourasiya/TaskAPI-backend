export const emailPurposeMapper = (purpose: string): string => {
	switch (purpose) {
		case "verifyEmailOR":
			return "Email Verification for New Registration on TaskAPI";
		case "verifyEmailUP":
			return "Email Verification for Email Update on TaskAPI";
		case "resetPassword":
			return "Password Reset Verification for Your TaskAPI Account";
		case "account_recovery":
			return "Account Recovery Verification for Your TaskAPI Account";
		case "resend_otp":
			return "OTP Verification for Your TaskAPI Account";
		default:
			return "Email Verification";
	}
};
