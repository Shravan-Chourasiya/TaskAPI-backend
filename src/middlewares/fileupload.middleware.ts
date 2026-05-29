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
		if (!req.headers["content-type"]?.includes("multipart/form-data")) {
			return next();
		}

		// Try to get file, but don't fail if missing
		try {
			console.warn("File upload middleware: Attempting to process file upload...");
			const file = await handleAvatarUpload(req);
			console.warn("File upload middleware: File obtained, uploading to Cloudinary...", { fileName: file.originalname });
			const fileUrl = await uploadToCloudinary(file);
			console.warn("File upload middleware: File uploaded to Cloudinary, URL obtained:", fileUrl);
			req.body.avatarUrl = fileUrl;
		} catch (fileError) {
			// If no file uploaded, just continue without fileUrl
			// Only throw if it's an actual error (not "no file" error)
			if (
				fileError instanceof Error &&
				!fileError.message.includes("No avatar file uploaded")
			) {
				throw fileError;
			}
		}
		const { firstName, lastName, bio, avatarUrl, country, city } =
			req.body;

		req.body = {
			newValue: {
				firstName,
				lastName,
				bio,
				avatarUrl: avatarUrl || "",
				country,
				city
			},
		};

		next();
	} catch (error) {
		next(error);
	}
};
