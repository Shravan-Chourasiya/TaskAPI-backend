import type { Model, Document, Types } from "mongoose";

export type SessionType = {
	csrfToken?: string;
	userId: string;
	deviceId: string;
	userAgent: string;
	ipAddress: string;
	ipCountry?: string;
	ipRegion?: string;
	ipCity?: string;
	activeSessions: number;
	sessionDevices: string[];
	refreshTokenHash: string;
	tokenFamily: string;
	status: "active" | "revoked" | "expired";
	isRevoked: boolean;
	revokedAt: Date;
	lastActivityAt: Date;
	accessTokenExpiresAt: Date;
	refreshTokenExpiresAt: Date;
};

// Instance methods interface
export interface SessionInstanceMethods {
	revoke(reason?: string): Promise<void>;
	updateActivity(): Promise<void>;
	isValid(): boolean;
}

// Static methods interface
export interface SessionStaticMethods extends Model<
	SessionType,
	object,
	SessionInstanceMethods
> {
	findActiveSessions(userId: string): Promise<SessionDocument[]>;
	revokeAllUserSessions(userId: string, reason?: string): Promise<void>;
	findByTokenFamily(tokenFamily: string): Promise<SessionDocument[]>;
	countActiveSessions(userId: string): Promise<number>;
}

// Combined document type
export type SessionDocument = Document<Types.ObjectId, object, SessionType> &
	SessionType &
	SessionInstanceMethods;
