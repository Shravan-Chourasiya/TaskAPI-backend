import { Request, Response, NextFunction, RequestHandler } from "express";

type AsyncFn<TModel> = (
	req: Request,
	res: Response,
	next: NextFunction,
	model: TModel,
) => Promise<void | Response>;

export function createMiddlewareWrapper<TModel>(
	model: TModel,
	fn: AsyncFn<TModel>,
	asyncErrorHandler: (fn: (req: Request, res: Response, next: NextFunction) => Promise<void | Response>) => RequestHandler,
): RequestHandler {
	return asyncErrorHandler((req, res, next) => fn(req, res, next, model));
}
