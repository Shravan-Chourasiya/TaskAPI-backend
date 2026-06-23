import { defineConfig } from "drizzle-kit";
import { config } from "./src/configs/app.config.js";

export default defineConfig({
	schema: "./scripts/pg_schema.ts",
	out: "./scripts/migrations",
	dialect: "postgresql",
	dbCredentials: {
		url: config.POSTGRES_DB_URI,
	},
});
