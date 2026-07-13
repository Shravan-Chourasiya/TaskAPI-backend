import express from "express";
import { ClientUserStaticMethods } from "../modules/clientauth/types/userMongo.type.js";
import { ApiKeyStaticMethods } from "../types/mongoModels/apikeys.type.js";
import * as clientAdminControllers from "../modules/clientauth/controllers/clientAdmin.controller.js";
import { apikeyHandlerFunction } from "../middlewares/apikeyhandler.middleware.js";
import { createMiddlewareWrapper } from "../utils/middlewareWrapper.js";
import { asyncErrorHandler } from "../utils/asynchandler.utils.js";

export function createClientAdminRouter({
	clientUserModel,
	apiKeyModel,
}: {
	clientUserModel: ClientUserStaticMethods;
	apiKeyModel: ApiKeyStaticMethods;
}): express.Router {
	const router = express.Router();

	const apikeyHandler = createMiddlewareWrapper(
		apiKeyModel,
		apikeyHandlerFunction,
		asyncErrorHandler,
	);

	router.use(apikeyHandler);

	router.get("/users", (req, res, next) =>
		clientAdminControllers.getAllUsersList(req, res, next, clientUserModel),
	);

	router.get("/users/:f", (req, res, next) =>
		clientAdminControllers.getFilteredUsersList(req, res, next, clientUserModel),
	);

	router.post("/users", (req, res, next) =>
		clientAdminControllers.addUser(req, res, next, clientUserModel),
	);

	router.delete("/users/:userId/delete", (req, res, next) =>
		clientAdminControllers.deleteUser(req, res, next, clientUserModel),
	);

	router.patch("/users/:userId", (req, res, next) =>
		clientAdminControllers.modifyUser(req, res, next, clientUserModel),
	);

	router.patch("/users/:id/blacklist", (req, res, next) =>
		clientAdminControllers.blackListOrBlockUser(req, res, next, clientUserModel),
	);

	router.patch("/users/:id/unblacklist", (req, res, next) =>
		clientAdminControllers.unBlackListUser(req, res, next, clientUserModel),
	);

	return router;
}
