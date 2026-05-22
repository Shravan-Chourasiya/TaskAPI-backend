interface ApiResponse {
	success: boolean;
	data?: object | null;
	message: string;
}
export const standardResponse = (
	success: boolean,
	message: string,
	data: object | null = null,
): ApiResponse => {
	return {
		success,
		message,
		data,
	};
};

export const tokenMiddlewareResponse = (
	success: boolean,
	message: string,
	tokenExpired: boolean = true,
): ApiResponse => {
	return {
		success,
		message,
		data: {
			tokenExpired,
		},
	};
};

export const isUserResponse = (
	isUser: boolean,
	message: string,
	user: object | null,
	success: boolean,
): ApiResponse => {
	return {
		success,
		message,
		data: {
			isUser,
			user,
		},
	};
};
