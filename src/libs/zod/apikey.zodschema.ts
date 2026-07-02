import * as z from "zod";
import { isIP } from "net";

export const apiKeyCreationSchema = z.object({
	name: z.string().min(5).max(50),
	description: z.string().min(10).max(300).optional(),
	env: z.enum(["production", "development", "test"]),
	scopes: z.array(z.string().min(1)).min(1),
	allowedIPs: z.array(z.string()).default(["0.0.0.0"]).optional(),
});

export const updateApiKeySchema = z.object({
	keyId: z.string().min(1),
	keyUpdatesDetails: z.object({
		name: z.string().min(5).max(50).optional(),
		description: z.string().min(10).max(300).optional(),
		scopes: z.array(z.string().min(1)).min(1).optional(),
		allowedIPs: z.array(z.string()).optional(),
		keyStatus: z.enum(["active", "inactive"]).optional(),
	}).strict().refine(
		(data) => Object.keys(data).length > 0,
		{ message: "At least one field must be provided for update" },
	),
});