import  { Schema, Model, Connection } from "mongoose";
import { IRollupBucket } from "../types/rollupData.type.js";


// Generalised schema creation function for rollup buckets. Each granularity has its own collection.
function createRollupSchema(): Schema<IRollupBucket> {
	const schema = new Schema<IRollupBucket>(
		{
			apiKeyId: { type: Schema.Types.ObjectId, required: true, index: false },
			bucketStart: { type: Date, required: true },
			granularity: { type: String, required: true },

			successCount: { type: Number, default: 0 },
			errorCount: { type: Number, default: 0 },

			successDurationSum: { type: Number, default: 0 },
			errorDurationSum: { type: Number, default: 0 },

			minDuration: { type: Number, default: null },
			maxDuration: { type: Number, default: null },

			expiresAt: { type: Date, required: true },
		},
		{ versionKey: false, minimize: true },
	);

	// --- INDEX 1: primary query + uniqueness index ---
	// ESR rule (Equality, Sort, Range): apiKeyId is equality-filtered on every
	// dashboard read, bucketStart is both the sort key AND the range filter.
	// This single compound index covers: upsert dedup, range queries, and
	// sorted results — no in-memory sort stage needed.
	schema.index({ apiKeyId: 1, bucketStart: 1 }, { unique: true });

	// --- INDEX 2: TTL index ---
	// Must be a single-field index — TTL doesn't work on compound indexes.
	// expiresAt is precomputed at insert time (bucketStart + retention),
	// so this index doesn't need to know the retention window itself.
	schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

	return schema;
}


// Rollup Models Initialization With Connection to DB as param
export function createRollupModels(conn: Connection) {
	const schema5m = createRollupSchema();
	const schema1h = createRollupSchema();
	const schema1d = createRollupSchema();

	const Rollup5m: Model<IRollupBucket> = conn.model(
		"Rollup5m",
		schema5m,
		"rollups_5m",
	);

	const Rollup1h: Model<IRollupBucket> = conn.model(
		"Rollup1h",
		schema1h,
		"rollups_1h",
	);

	const Rollup1d: Model<IRollupBucket> = conn.model(
		"Rollup1d",
		schema1d,
		"rollups_1d",
	);

	return { Rollup5m, Rollup1h, Rollup1d };
}
