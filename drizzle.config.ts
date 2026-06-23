import { defineConfig } from "drizzle-kit";
import { config } from "./src/configs/app.config.js";

export default defineConfig({
	schema: "./src/modules/clientauth/schemas/*.ts",
	out: "./migrations",
	dialect: "postgresql",
	dbCredentials: {
		url: config.POSTGRES_DB_URI,
	},
});
