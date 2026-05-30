import multer, { FileFilterCallback } from "multer";
import type { Request, Response } from "express";
import { FILE_UPLOAD_CONSTANTS } from "../constants.js";

// Allow only image files
const imageFileFilter = (
	req: Request,
	file: Express.Multer.File,
	cb: FileFilterCallback,
) => {
	if (file.mimetype.startsWith("image/")) {
		cb(null, true);
	} else {
		cb(new Error("Only image files are allowed!"));
	}
};

// Use memory storage (no disk writes)
const storage = multer.memoryStorage();

// Create Multer instance
const upload = multer({
	storage,
	fileFilter: imageFileFilter,
	limits: { fileSize: FILE_UPLOAD_CONSTANTS.MAX_FILE_SIZE },
});

// Function that returns the file object
export function handleAvatarUpload(req: Request): Promise<Express.Multer.File> {
	return new Promise((resolve, reject) => {
		const middleware = upload.single(FILE_UPLOAD_CONSTANTS.AVATAR_FIELD_NAME);

		middleware(req, {} as Response, (err: unknown) => {
			if (err) {return reject(err)};
			if (!req.file) {return reject(new Error("No avatar file uploaded"))};
			resolve(req.file);
		});
	});
}
