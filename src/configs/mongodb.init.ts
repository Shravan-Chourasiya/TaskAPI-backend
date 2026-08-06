import mongoose from "mongoose";
import { config } from "./app.config.js";
import { logger } from "../utils/logger.utils.js";

type ClusterConnType = mongoose.Mongoose | null | undefined;

async function dbConnect() {
	const uri: string = config.MONGO_URI;
	try {
		const isConnectionExists = mongoose.connection.readyState;
		if (isConnectionExists === 1) {
			logger.info("Mongo Cluster Connection Already Established !");
		} else {
			const clusterConn: ClusterConnType = await mongoose.connect(uri);
			logger.info("Mongo Cluster Connected Successfully!");
			return clusterConn;
		}
	} catch (error) {
		logger.error("ERR:DB CONNECTION FAILED", { error });
		process.exit(1);
	}
}

export default dbConnect;

export function getDbConnection(dbName: string, clusterConn: ClusterConnType) {
	if (!clusterConn) throw new Error("Cluster not connected yet!");
	return clusterConn.connection.useDb(dbName);
}
