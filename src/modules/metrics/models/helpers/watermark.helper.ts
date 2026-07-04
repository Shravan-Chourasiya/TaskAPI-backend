import { Model } from "mongoose";
import { IRollupWatermark, RollupJobName } from "../../types/watermark.type.js";

// HELPER: get-or-create (handles first-ever run safely)
export async function getOrCreateWatermark(
	Watermark: Model<IRollupWatermark>,
	jobName: RollupJobName,
	seedAt: Date = new Date(),
): Promise<IRollupWatermark> {
	const existing = await Watermark.findOne({ jobName }).lean();
	if (existing) return existing;

	try {
		const created = await Watermark.create({
			jobName,
			lastProcessedAt: seedAt,
			status: "idle",
			updatedAt: new Date(),
			lastError: null,
			lastRunDurationMs: null,
		});
		return created.toObject();
	} catch (err: any) {
		// Duplicate key = another worker instance created it concurrently — just re-read.
		if (err?.code === 11000) {
			const wm = await Watermark.findOne({ jobName }).lean();
			if (wm) return wm;
		}
		throw err;
	}
}

// HELPER: mark run as started
export async function markWatermarkRunning(
	Watermark: Model<IRollupWatermark>,
	jobName: RollupJobName,
): Promise<void> {
	await Watermark.updateOne(
		{ jobName },
		{ $set: { status: "running", updatedAt: new Date() } },
	);
}

// HELPER: advance watermark on success
export async function advanceWatermark(
	Watermark: Model<IRollupWatermark>,
	jobName: RollupJobName,
	newLastProcessedAt: Date,
	runDurationMs: number,
): Promise<void> {
	await Watermark.updateOne(
		{ jobName },
		{
			$set: {
				lastProcessedAt: newLastProcessedAt,
				status: "idle",
				updatedAt: new Date(),
				lastError: null,
				lastRunDurationMs: runDurationMs,
			},
		},
	);
}


// HELPER: mark run as failed (watermark stays put)
export async function markWatermarkFailed(
	Watermark: Model<IRollupWatermark>,
	jobName: RollupJobName,
	errorMessage: string,
): Promise<void> {
	await Watermark.updateOne(
		{ jobName },
		{
			$set: {
				status: "failed",
				updatedAt: new Date(),
				lastError: errorMessage,
			},
		},
		// lastProcessedAt intentionally untouched
	);
}
