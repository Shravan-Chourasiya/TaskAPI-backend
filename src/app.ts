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
import { initUserModel } from "./modules/auth/models/user.schema.js";
import { initSessionModel } from "./modules/auth/models/session.schema.js";
import { initApiKeyModel } from "./modules/auth/models/apikey.schema.js";
import { initSubscriptionModel } from "./modules/auth/models/subscription.schema.js";

const app = express();

// const PostgresDbConn = getPgPool();
// const postgresConnectionResult = await testPgConnection();

const mongoClusterConn = await dbConnect();
const TaskapiDb = getDbConnection(config.DB_NAME, mongoClusterConn);
const TaskapiClientsDb = getDbConnection(
	config.CLIENT_DB_NAME,
	mongoClusterConn,
);
const userModel = initUserModel(TaskapiDb);
const sessionModel = initSessionModel(TaskapiDb);
const apiKeyModel = initApiKeyModel(TaskapiDb);
const subscriptionModel = initSubscriptionModel(TaskapiDb);
const authRouter: express.Router = createAuthRouter({
	userModel,
	sessionModel,
});
const subscriptionRouter: express.Router = createSubscriptionRouter({
	userModel,
	subscriptionModel,
	sessionModel,
});
const generalRouter: express.Router = createGeneralRouter({ userModel, sessionModel });
const apiKeyRouter: express.Router = createApiKeyRouter({
	userModel,
	apiKeyModel,
});

const corsOptions = {
	origin: config.ALLOWED_ORIGINS,
	credentials: true,
	optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};

app.use(express.json());
app.use(cookieParser());
app.use(morgan(config.NODE_ENV === "production" ? "combined" : "development"));
app.use(cors(corsOptions));

app.use("/api/v1/auth", apiRateLimiter, authRouter);
app.use("/api/v1/", apiRateLimiter, generalRouter);
app.use("/api/v1/subscription", apiRateLimiter, subscriptionRouter);
app.use("/api/v1/api-keys", apiRateLimiter, apiKeyRouter);

export { app };
