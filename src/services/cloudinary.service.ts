import {
	v2 as cloudinary,
	type UploadApiResponse,
	type UploadApiErrorResponse,
} from "cloudinary";
import { config } from "../configs/app.config.js";

export const v2Config = cloudinary.config({
	cloudinary_url: config.CLOUDINARY_URL,
});

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
