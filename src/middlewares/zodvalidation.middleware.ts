import type { Request, Response, NextFunction } from "express";
import { type ZodSchema, ZodError } from "zod";

export const ZodValidatorMiddleware = (schema: ZodSchema) => {
	return (req: Request, res: Response, next: NextFunction) => {
		try {
			// console.warn(req));
			schema.parse(req.body);
			next();
		} catch (error) {
			if (error instanceof ZodError) {
				console.error("Zod Validation error:", error);
				return res.status(400).json({
					message: "Zod Validation failed",
					errors: error.issues.map((err) => ({
						field: err.path.join("."),
						message: err.message,
					})),
				});
			}
			next(error);
		}
	};
};
