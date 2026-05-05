export type OtpType={
    userId:string,
    email:string,
    phone?:string,
    otpHash:string,
    purpose:"emailVerification" | "emailChange" | "phoneVerification" | "passwordReset" | "accountRecovery" | "twoFactorAuth",
    otpStatus:"pending" | "verified" | "expired" | "failed",
    isUsed:boolean,
    usedAt:Date,
    attemptsLeft:number,
    failedAttempts:number,
    lastAttemptAt:Date,
    expiresAt:Date,
}