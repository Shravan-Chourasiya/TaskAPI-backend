import type { Request, Response, NextFunction } from "express";
import {
	uploadToCloudinary,
	uploadImageFromUrl,
} from "../services/cloudinary.service.js";
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
		let fileUrl: string | undefined;
		const isMultipart = req.headers["content-type"]?.includes("multipart/form-data");

		// Case 1: multipart/form-data → file upload
		if (isMultipart) {
			try {
				console.warn(
					"File upload middleware: Attempting to process file upload...",
				);
				const file = await handleAvatarUpload(req);
				console.warn(
					"File upload middleware: File obtained, uploading to Cloudinary...",
					{ fileName: file.originalname },
				);
				fileUrl = await uploadToCloudinary(file);
				console.warn(
					"File upload middleware: File uploaded to Cloudinary, URL obtained:",
					fileUrl,
				);
			} catch (fileError) {
				if (
					fileError instanceof Error &&
					!fileError.message.includes("No avatar file uploaded")
				) {
					throw fileError;
				}
				// If no file uploaded in multipart, continue without fileUrl
			}

			// Extract other fields from multipart form
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
		} 
		// Case 2: Normal JSON form → user provides an image URL in body
		else if (
			req.body?.newValue?.avatarUrl &&
			typeof req.body.newValue.avatarUrl === "string"
		) {
			const urlString = req.body.newValue.avatarUrl.trim();

			// Validate URL format
			let parsedUrl: URL;
			try {
				parsedUrl = new URL(urlString);
			} catch {
				return res.status(400).json({
					success: false,
					message: "Invalid image URL format",
				});
			}

			// Security: Block internal/private IPs and localhost
			if (
				parsedUrl.protocol !== "https:" ||
				parsedUrl.hostname === "localhost" ||
				parsedUrl.hostname === "127.0.0.1" ||
				parsedUrl.hostname.startsWith("192.168.") ||
				parsedUrl.hostname.startsWith("10.") ||
				parsedUrl.hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./) // 172.16.0.0 - 172.31.255.255
			) {
				return res.status(400).json({
					success: false,
					message: "Invalid or restricted image URL",
				});
			}

			try {
				console.warn(
					"File upload middleware: User provided image URL, uploading to Cloudinary...",
				);
				fileUrl = await uploadImageFromUrl(urlString);
				console.warn(
					"File upload middleware: Image URL uploaded to Cloudinary, URL obtained:",
					fileUrl,
				);
				
				// Replace the URL with Cloudinary URL
				req.body.newValue.avatarUrl = fileUrl;
			} catch (urlError) {
				return res.status(400).json({
					success: false,
					message:
						urlError instanceof Error
							? `Failed to upload image from URL: ${urlError.message}`
							: "Failed to upload image from URL",
				});
			}
		}
		// Case 3: Normal JSON form without avatarUrl - just pass through
		else {
			// No file or URL, just continue with existing body
		}

		next();
	} catch (error) {
		next(error);
	}
};
