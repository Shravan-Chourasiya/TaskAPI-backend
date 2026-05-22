import multer, { FileFilterCallback } from "multer";
import type { Request, Response } from "express";

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
	limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB limit
});

// Function that returns the file object
export function handleAvatarUpload(req: Request): Promise<Express.Multer.File> {
	return new Promise((resolve, reject) => {
		const middleware = upload.single("avatar");

		middleware(req, {} as Response, (err: unknown) => {
			if (err) {return reject(err)};
			if (!req.file) {return reject(new Error("No avatar file uploaded"))};
			resolve(req.file);
		});
	});
}
