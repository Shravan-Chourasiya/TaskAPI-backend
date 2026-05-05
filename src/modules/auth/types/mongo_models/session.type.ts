export type SessionType = {
	userId: string;
	deviceId: string;
	deviceInfo: {
		userAgent: string;
		deviceType: "mobile" | "tablet" | "desktop";
		browser: string;
		os: string;
	};
	ipAddress: string;
	ipCountry?: string;
	ipRegion?: string;
	ipCity?: string;
	accessTokenHash: string;
	refreshTokenHash: string;
	tokenFamily: string;
	status: "active" | "revoked" | "expired";
	isRevoked: boolean;
	revokedAt: Date;
	lastActivityAt: Date;
	accessTokenExpiresAt: Date;
	refreshTokenExpiresAt: Date;
};
