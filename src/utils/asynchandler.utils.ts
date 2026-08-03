import { type Request, type Response, type NextFunction } from "express";
import { classifyError } from "../middlewares/errorhandler.middleware.js";
import { AppError } from "../types/errors.interface.js";

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
				console.error(`[${errSrc}] Server error:`, err);
				// TODO: Replace with proper logging mechanism (Winston, Pino, etc.)
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
