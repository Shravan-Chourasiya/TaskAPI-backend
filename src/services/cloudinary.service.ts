import {
	v2 as cloudinary,
	type UploadApiResponse,
	type UploadApiErrorResponse,
} from "cloudinary";
import { config } from "../configs/app.config.js";
import axios from "axios";
import streamifier from "streamifier";

export const v2Config = cloudinary.config({
	cloudinary_url: config.CLOUDINARY_URL,
});

// Independent function: takes a Multer file, returns Cloudinary URL
export async function uploadToCloudinary(
	file: Express.Multer.File,
	folder: string = "uploads",
): Promise<string> {
	return new Promise((resolve, reject) => {
		const stream = cloudinary.uploader.upload_stream(
			{ folder },
			(
				error: UploadApiErrorResponse | undefined,
				result: UploadApiResponse | undefined,
			) => {
				if (error) {
					return reject(error);
				}
				if (!result) {
					return reject(new Error("No result from Cloudinary"));
				}
				resolve(result.secure_url);
			},
		);

		stream.end(file.buffer);
	});
}

export async function uploadImageFromUrl(
	imageUrl: string,
): Promise<string> {
	try {
		// Fetch the image as a buffer with timeout
		const response = await axios.get(imageUrl, {
			responseType: "arraybuffer",
			timeout: 10000,
			maxContentLength: 5 * 1024 * 1024,
			headers: {
				"User-Agent": "TaskAPI-ImageUpload/1.0",
			},
		});

		// Validate content type is image
		const contentType = response.headers["content-type"];
		
		if (typeof contentType !== "string" || !contentType.startsWith("image/")) {
			throw new Error("URL does not point to a valid image");
		}

		const buffer = Buffer.from(response.data, "binary");

		// Upload to Cloudinary using a stream
		return new Promise((resolve, reject) => {
			const uploadStream = cloudinary.uploader.upload_stream(
				{ folder: "uploads" },
				(error, result) => {
					if (error) return reject(error);
					if (!result?.secure_url) {
						return reject(new Error("No secure URL from Cloudinary"));
					}
					resolve(result.secure_url);
				},
			);
			streamifier.createReadStream(buffer).pipe(uploadStream);
		});
	} catch (err: any) {
		throw new Error(`Upload failed: ${err.message}`);
	}
}
