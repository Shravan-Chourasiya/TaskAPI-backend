import express from "express";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import dbConnect, { getDbConnection } from "./configs/mongodb.init.js";
import { config } from "./configs/app.config.js";
import cors from "cors";
import { createAuthRouter } from "./routes/auth.routes.js";
import { apiRateLimiter } from "./middlewares/ratelimiting.middleware.js";
import { createSubscriptionRouter } from "./routes/subscription.routes.js";
import { createGeneralRouter } from "./routes/general.routes.js";
import { createApiKeyRouter } from "./routes/apikey.routes.js";
import { createClientUserRouter } from "./routes/clientUser.routes.js";
import { initUserModel } from "./modules/auth/models/user.schema.js";
import { initSessionModel } from "./modules/auth/models/session.schema.js";
import { initApiKeyModel } from "./modules/auth/models/apikey.schema.js";
import { initSubscriptionModel } from "./modules/auth/models/subscription.schema.js";
import { initClientUserModel } from "./modules/clientauth/schemas/userMongo.schema.js";
import { initRawEventModel } from "./modules/metrics/models/rawEvent.schema.js";
import { createMetricsMiddleware } from "./middlewares/metricsCollector.middleware.js";
import { BASE_URL } from "./constants.js";
import { initWatermarkModel } from "./modules/metrics/models/watermark.schema.js";
import { createRollupModels } from "./modules/metrics/models/rollupData.schema.js";
import { initRollupWorkers } from "./libs/bullmq/workers/metricsWorker.js";
import { createRollupProcessor } from "./libs/bullmq/controllers/metricsworkers.controller.js";

// =================== Server Initialization ===================

const app = express();

// =================== Database Initializations ===================

//const PostgresDbConn = getPgPool();
//const postgresConnectionResult = await testPgConnection();
const mongoClusterConn = await dbConnect();
const TaskapiDb = getDbConnection(config.DB_NAME, mongoClusterConn);
const TaskapiClientsDb = getDbConnection(
	config.CLIENT_DB_NAME,
	mongoClusterConn,
);

// =================== Db Models Initializations ===================

const userModel = initUserModel(TaskapiDb);
const sessionModel = initSessionModel(TaskapiDb);
const apiKeyModel = initApiKeyModel(TaskapiDb);
const subscriptionModel = initSubscriptionModel(TaskapiDb);
const clientUserModel = initClientUserModel(TaskapiClientsDb);
const rawEventsClientModel = initRawEventModel(TaskapiClientsDb);
const watermarkModel = initWatermarkModel(TaskapiClientsDb);
const { Rollup5m, Rollup1h, Rollup1d } = createRollupModels(TaskapiClientsDb);
//alias kept for readability during transition
const clientUsersStoreModel = clientUserModel;


// Metrics Workers Initialization
initRollupWorkers(
	{
		watermarkModel,
		rawEventModel: rawEventsClientModel,
		rollup5mModel: Rollup5m,
		rollup1hModel: Rollup1h,
		rollup1dModel: Rollup1d,
	},
	createRollupProcessor,
);

// =================== Api Routers Initialization ===================

const authRouter: express.Router = createAuthRouter({
	userModel,
	sessionModel,
});
const subscriptionRouter: express.Router = createSubscriptionRouter({
	userModel,
	subscriptionModel,
	sessionModel,
});
const generalRouter: express.Router = createGeneralRouter({
	userModel,
	sessionModel,
});
const apiKeyRouter: express.Router = createApiKeyRouter({
	userModel,
	apiKeyModel,
});
const clientUserRouter: express.Router = createClientUserRouter({
	userModel: clientUserModel,
	apiKeyModel,
});

// =================== Cors Configuration ===================

const corsOptions = {
	origin: config.ALLOWED_ORIGINS,
	credentials: true,
	//some legacy browsers (IE11, various SmartTVs) choke on 204
	optionsSuccessStatus: 200,
};

// =================== Server level Middlwares ===================

app.use(express.json());
app.use(cookieParser());
app.use(morgan(config.NODE_ENV === "production" ? "combined" : "development"));
app.use(cors(corsOptions));
app.use(createMetricsMiddleware(rawEventsClientModel));

// =================== Routes Integration ===================

app.use(`${BASE_URL}/auth`, apiRateLimiter, authRouter);
app.use(`${BASE_URL}/subscription`, apiRateLimiter, subscriptionRouter);
app.use(`${BASE_URL}/api-keys`, apiRateLimiter, apiKeyRouter);
app.use(`${BASE_URL}/client/auth`, apiRateLimiter, clientUserRouter);

app.use(`${BASE_URL}/`, apiRateLimiter, generalRouter);

export { app };
