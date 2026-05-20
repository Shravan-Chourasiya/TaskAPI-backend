import type { NextFunction, Request, Response } from "express";
import { config } from "../configs/app.config.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import userModel from "../modules/auth/models/user.schema.js";

export const isUserController = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		// This endpoint is protected by accessTokenHandler, so if we reach here, the user is verified
		const decoded = jwt.verify(req.cookies.acToken, config.ACCESS_TOKEN_JWT_SECRET) as JwtPayload;
		if (!decoded) {
			return res.status(401).json({isUser: false, message: "Invalid token" });
		}
		const user=await userModel.findById(decoded.id);
		if(!user){
			return res.status(404).json({isUser: false, message: "User not found" });
		}
		if(user.status !== "active"){
			return res.status(403).json({isUser: false, message: "User is not verified or Account is Inactive/Suspended" });
		}
		const userObj={
			username: user.username,
			email: user.email,
			status: user.status,
			role: user.roles
		};
		res.status(200).json({isUser: true, message: "User is verified", user: userObj });
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
