export const emailPurposeMapper = (purpose: string): string => {
	switch (purpose) {
		case "verifyEmailOR":
		case "ve-em-or":
			return "Email Verification for New Registration on TaskAPI";
		case "verifyEmailUP":
		case "ve-em-up":
			return "Email Verification for Email Update on TaskAPI";
		case "ve-em-cu":
			return "Confirm Your Current Email - TaskAPI";
		case "resetPassword":
		case "fr-pa":
			return "Password Reset Verification for Your TaskAPI Account";
		case "up-pa":
			return "Confirm Password Change - TaskAPI";
		case "accountRecovery":
		case "ac-re":
			return "Account Recovery Verification for Your TaskAPI Account";
		case "resendOtp":
			return "OTP Verification for Your TaskAPI Account";
		case "forgotPassword":
			return "Password Reset Verification for Your TaskAPI Account";
		case "deleteAccount":
			return "Account Deletion Scheduled for Your TaskAPI Account";
		default:
			return "Email Verification";
	}
};
