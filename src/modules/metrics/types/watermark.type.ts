export type RollupJobName = "rollup_5m" | "rollup_1h" | "rollup_1d";

export type WatermarkStatus = "idle" | "running" | "failed";

export interface IRollupWatermark {
	jobName: RollupJobName; // unique — one doc per rollup tier
	lastProcessedAt: Date; // cursor: end of last successfully processed window
	status: WatermarkStatus; // current job state
	updatedAt: Date; // last time this doc was written
	lastError: string | null; // last failure reason, if any (for alerting/debugging)
	lastRunDurationMs: number | null; // optional: how long the last successful run took
}
