import type { Request, Response, NextFunction } from "express";
import { uploadToCloudinary } from "../services/cloudinary.service.js";
import { handleAvatarUpload } from "../services/multer.service.js";

export interface RequestWithFileUrl extends Request {
	fileUrl?: string;
}

export const fileUploadMiddleware = async (
	req: RequestWithFileUrl,
	res: Response,
	next: NextFunction,
) => {
	try {
		// amazonq-ignore-next-line
		const contentType: string = Array.isArray(req.headers["content-type"])
			? req.headers["content-type"].join(",")
			: req.headers["content-type"] ?? "";

		if (!contentType.includes("multipart/form-data")) {
			// Non-multipart: pass through as-is (JSON profile update without file)
			return next();
		}

		let fileUrl: string | undefined;
		try {
			const file = await handleAvatarUpload(req);
			fileUrl = await uploadToCloudinary(file);
		} catch (fileError) {
			if (
				fileError instanceof Error &&
				!fileError.message.includes("No avatar file uploaded")
			) {
				throw fileError;
			}
		}

		const { firstName, lastName, bio, country, city } = req.body;
		req.body = {
			newValue: {
				...(firstName && { firstName }),
				...(lastName && { lastName }),
				...(bio && { bio }),
				...(fileUrl && { avatarUrl: fileUrl }),
				...(country && { country }),
				...(city && { city }),
			},
		};

		next();
	} catch (error) {
		next(error);
	}
};
