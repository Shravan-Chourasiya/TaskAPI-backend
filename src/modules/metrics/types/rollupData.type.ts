import mongoose from "mongoose";

export type RollupGranularity = "5m" | "1h" | "1d";

export interface IRollupBucket {
	apiKeyId: mongoose.Types.ObjectId; // reference to the API key, not the raw key
	bucketStart: Date; // start of this time bucket (UTC, aligned)
	granularity: RollupGranularity;

	successCount: number;
	errorCount: number;

	successDurationSum: number; // ms, sum — never store avg directly
	errorDurationSum: number; // ms, sum

	minDuration: number;
	maxDuration: number;

	expiresAt: Date; // precomputed = bucketStart + retention, TTL target
}
