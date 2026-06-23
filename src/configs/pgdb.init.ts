import { drizzle } from "drizzle-orm/node-postgres";
import { Pool, type PoolConfig } from "pg";
import { config } from "./app.config.js";

let pool: Pool | undefined;
let db: ReturnType<typeof drizzle> | undefined;

export function getPgDb() {
	if (db) {
		return db;
	}

	if (!pool) {
		const poolConfig: PoolConfig = {
			connectionString: config.POSTGRES_DB_URI,
			ssl: {
				rejectUnauthorized: false,
			},
			max: 5,
			idleTimeoutMillis: 10_000,
			connectionTimeoutMillis: 15_000,
		};

		pool = new Pool(poolConfig);
	}

	db = drizzle({ client: pool });
	return db;
}

export async function testPgConnection() {
	const pgDb = getPgDb();
	const result = await pgDb.execute("select 1");
	return result;
}

export function getPgPool() {
	if (!pool) {
		getPgDb();
	}

	return pool as Pool;
}

export default getPgDb;
