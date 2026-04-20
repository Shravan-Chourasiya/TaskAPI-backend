import mongoose from "mongoose";
import type { UserModel } from "../types/dbModel.interface.js";

const userSchema = new mongoose.Schema({
	username: {
		type: String,
		required: [true, "Username is Required to Register"],
		unique: [true, "Username already Taken!"],
	},
	email: {
		type: String,
		required: [true, "Email is Required to Register"],
		unique: true,
	},
	password: {
		type: String,
		required: true,
	},
	isVerified: {
		type: Boolean,
		default: false,
	},
	isDeleted: {
		type: Boolean,
		default: false,
	},
	expiresAt: {
		type: Date,
		default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
	},
});

userSchema.index(
	{ expiresAt: 1 },
	{
		expireAfterSeconds: 0,
		partialFilterExpression: { isDeleted: true },
	},
);
export const userModel = mongoose.model<UserModel>("Users", userSchema);
