import type { Request, Response, NextFunction } from "express";
import type { ZodSchema } from "zod";
import { ZodValidatorMiddleware } from "./zodvalidation.middleware.js";
import { standardResponse } from "../utils/apiResponse.utils.js";

/**
 * createPurposeValidatorMiddleware
 *
 * Validates ?purpose= query param against a provided map of { purposeValue: ZodSchema }.
 * If purpose is valid and has a mapped schema, runs Zod body validation before next().
 * If purpose is valid but has no mapped schema, passes through to controller.
 * Rejects unknown purposes immediately with 400.
 *
 * @param schemaMap   - { [purposeValue]: ZodSchema } — body schema per purpose
 * @param validPurposes - readonly array of all accepted purpose values (from CLIENT_OTP_PURPOSES)
 */
export function createPurposeValidatorMiddleware(
	schemaMap: Record<string, ZodSchema>,
	validPurposes: readonly string[],
) {
	return (req: Request, res: Response, next: NextFunction): void => {
		const purpose = req.query.purpose;

		if (!purpose || typeof purpose !== "string") {
			res.status(400).json(standardResponse(false, "?purpose query param is required"));
			return;
		}

		if (!validPurposes.includes(purpose)) {
			res.status(400).json(
				standardResponse(false, `Invalid purpose. Must be one of: ${validPurposes.join(", ")}`),
			);
			return;
		}

		const schema = schemaMap[purpose];
		if (schema) {
			ZodValidatorMiddleware(schema)(req, res, next);
			return;
		}

		next();
	};
}
