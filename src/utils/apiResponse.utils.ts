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


export const isUserResponse = (
	success: boolean,
	message: string,
	isUser: boolean,
	user: object | null,
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

	export const tokenMiddlewareResponse = (
		success: boolean,
		message: string,
		error?: string,
		requiresReAuth: boolean = true,
	): ApiResponse => {
		return {
			success,
			message,
			data: {
				error,
				requiresReAuth,
			},
		};	
	};