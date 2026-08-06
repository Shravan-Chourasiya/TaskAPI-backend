import { type Request, type Response, type NextFunction } from "express";
import { classifyError } from "../middlewares/errorhandler.middleware.js";
import { AppError } from "../types/errors.interface.js";
import { logger } from "./logger.utils.js";

type AsyncFn = (
	req: Request,
	res: Response,
	next: NextFunction,
) => Promise<void | Response>;

export const asyncErrorHandler = (fn: AsyncFn) => {
	return async (req: Request, res: Response, next: NextFunction) => {
		try {
			await fn(req, res, next);
		} catch (err) {
			const { status, message, errSrc } = classifyError(err);

			// Stamp machine-readable error code for the metrics collector.
			res.locals.errorCode = AppError.isAppError(err) ? err.code : errSrc;

			// Log server errors
			if (status >= 500) {
				logger.error(`[${errSrc}] ${req.method} ${req.originalUrl}: ${message}`, {
					stack: err && typeof err === "object" && "stack" in err ? (err as Error).stack : undefined,
				});
			}

			// Send single response
			return res.status(status).json({
				success: false,
				error: errSrc,
				message,
			});
		}
	};
};
