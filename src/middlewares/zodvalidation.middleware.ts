import type { Request, Response, NextFunction } from "express";
import { type ZodSchema, ZodError } from "zod";

export const ZodValidatorMiddleware = (schema: ZodSchema) => {
	return (req: Request, res: Response, next: NextFunction) => {
		try {
			// console.warn(req)
			// console.warn("Validating request body:", req.body);
			schema.parse(req.body);
			next();
		} catch (error) {
			if (error instanceof ZodError) {
				return res.status(400).json({
					message: "Validation failed",
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
