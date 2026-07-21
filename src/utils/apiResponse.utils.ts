import type { Request, Response } from "express";

interface ApiResponse {
	success: boolean;
	data?: object | null;
	message: string;
}
export const standardResponse = (
	success: boolean,
	message: string,
	data: object | null | object[] = null,
): ApiResponse => {
	return {
		success,
		message,
		data,
	};
};

export const isUserResponse = (
	success: boolean,
	message: string,
	isUser: boolean,
	user: object | null,
): ApiResponse => {
	return {
		success,
		message,
		data: {
			isUser,
			user,
		},
	};
};

export const tokenMiddlewareResponse = (
	success: boolean,
	message: string,
	error?: string,
	requiresReAuth: boolean = true,
): ApiResponse => {
	return {
		success,
		message,
		data: {
			error,
			requiresReAuth,
		},
	};
};

/**
 * Set CSRF token header, and also include it in the response body
 * if the request is from Postman (no way to read custom headers in Postman easily).
 */
export function sendCsrfResponse(
	req: Request,
	res: Response,
	csrfToken: string,
	statusCode: number,
	body: object,
): void {
	const isPostman = req.headers["user-agent"]?.startsWith("PostmanRuntime/");

	res.setHeader("X-CSRF-Token", csrfToken);

	if (isPostman && body) {
		(body as Record<string, unknown>).csrfToken = csrfToken;
	}

	res.status(statusCode).json(body);
}
