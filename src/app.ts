import express, {
	type NextFunction,
	type Request,
	type Response,
} from "express";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import dbConnect from "./configs/db.js";
import { config } from "./configs/configs.js";
import { classifyError } from "./middlewares/errorhandler.middleware.js";
import { rateLimitMiddleware } from "./middlewares/ratelimiting.middleware.js";
import cors from "cors";
import { authRouter } from "./routes/auth.routes.js";
const app = express();

await dbConnect();

const corsOptions = {
	origin: config.ALLOWED_ORIGINS,
	credentials: true,
	optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};

app.use(express.json());
app.use(cookieParser());
app.use(morgan(config.NODE_ENV === "production" ? "combined" : "development"));
app.use(cors(corsOptions));

app.use("/api/v1/auth", rateLimitMiddleware, authRouter);

app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
	const { status, message } = classifyError(err);
	res.status(status).json({ error: message });
});

export { app };
