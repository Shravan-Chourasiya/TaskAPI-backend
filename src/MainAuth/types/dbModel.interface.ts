export interface UserModel {
    _id: string;
    username: string;
    email: string;
    password: string;
    isVerified: boolean;
    isDeleted:boolean;
    createdAt: Date;
    updatedAt: Date;
}

export interface OTPModel {
    _id: string;
    otp: string;    
    email: string;
    userId:string;
    purpose: "verifyEmailOR" | "verifyEmailUP" | "resetPassword" | "account_recovery";
    fieldToUpdateNewValue?: string;
    isTemp: boolean;
    isUsed: boolean;
    attemptsLeft: number;
    expiryTime: Date;
    createdAt: Date;
    updatedAt: Date;
}

export interface SessionModel{
    userId: string;
    userIP: string;
    userAgents: string;
    refreshToken: string;
    isRevoked: boolean;
    expiresAt: Date;
    createdAt: Date;
    updatedAt: Date;
}