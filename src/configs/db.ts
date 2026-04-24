import mongoose from "mongoose";
import { config } from "./configs.js";

async function dbConnect() {
	const uri: string = config.MONGO_URI as string;
	const dbname = config.DB_NAME as string;
	try {
		const isConnectionExists = mongoose.connection.readyState;
		if (isConnectionExists === 1) {
			console.log("Database Connection Already Established Successfully!");
		} else {
			await mongoose.connect(uri, {
				dbName: dbname,
			});
			console.log("Database Connected Successfully!");
		}
	} catch (error) {
		console.error("ERR:DB CONNECTION FAILED", error);
		process.exit(1);
	}
}
export default dbConnect;
