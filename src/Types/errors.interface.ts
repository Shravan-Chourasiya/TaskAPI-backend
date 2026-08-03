/**
 * AppError — application-level error carrying a stable machine-readable code
 * and an HTTP status. Thrown by controllers/services and handled centrally by
 * Express error middleware.
 *
 * `code` is propagated into the raw metrics event's `error` field so that
 * `/site-admin/api-stats/errors`, `/audit-logs/errors` and
 * `/audit-logs/security-events` can group/filter by a stable label
 * (e.g. "VALIDATION_ERROR", "INVALID_API_KEY").
 */
export class AppError extends Error {
	code: string;
	statusCode: number;

	constructor(code: string, message: string, statusCode = 500) {
		super(message);
		this.name = "AppError";
		this.code = code;
		this.statusCode = statusCode;
	}

	static isAppError(err: unknown): err is AppError {
		return err instanceof AppError;
	}
}

export interface NodemailerError extends Error {
	code?: string; // e.g. 'EAUTH', 'ECONNECTION', 'ETIMEDOUT'
	command?: string; // SMTP command during failure
	response?: string; // Raw SMTP response
	responseCode?: number; // Numeric SMTP code (e.g. 535)
	rejected?: string[]; //Invalid recipeints addresses
}
