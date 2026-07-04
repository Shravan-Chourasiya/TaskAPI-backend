import { Schema, Model, Connection } from "mongoose";
import { IRollupWatermark } from "../types/watermark.type.js";

const rollupWatermarkSchema = new Schema<IRollupWatermark>(
	{
		jobName: {
			type: String,
			required: true,
			enum: ["rollup_5m", "rollup_1h", "rollup_1d"],
		},
		lastProcessedAt: {
			type: Date,
			required: true,
		},
		status: {
			type: String,
			enum: ["idle", "running", "failed"],
			default: "idle",
			required: true,
		},
		updatedAt: {
			type: Date,
			required: true,
			default: () => new Date(),
		},
		lastError: {
			type: String,
			default: null,
		},
		lastRunDurationMs: {
			type: Number,
			default: null,
		},
	},
	{
		versionKey: false,
		collection: "rollup_watermarks",
	},
);

// Only index needed: exactly one document per job, fetched by jobName every run.
// Tiny collection (3 docs total) — this index alone is more than sufficient.
rollupWatermarkSchema.index({ jobName: 1 }, { unique: true });

// ============== Model Initialization Function =============
export function initWatermarkModel(
	conn: Connection,
): Model<IRollupWatermark> {
	return conn.model<IRollupWatermark>(
		"RollupWatermark",
		rollupWatermarkSchema,
		"rollup_watermarks",
	);
}
