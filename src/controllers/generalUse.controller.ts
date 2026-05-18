import type { NextFunction, Request, Response } from "express";

export const isUserController = (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		// This endpoint is protected by accessTokenHandler, so if we reach here, the user is verified
		res.status(200).json({isUser: true, message: "User is verified" });
	} catch (error) {
		next(error);
	}
};


export const healthCheckController = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        res.status(200).json({ status: "OK", message: "Health check passed" });
    } catch (error) {
        next(error);
    }
};  
