export interface AppError extends Error {
	code?: string; // Nodemailer, network, JWT errors
	name: string; // Built-in JS errors (TypeError, SyntaxError)
	response?: string; // SMTP/HTTP responses
	responseCode?: number; // Numeric codes (SMTP, HTTP)
	rejected?: string[]; // Nodemailer invalid recipients
}

export interface NodemailerError extends Error {
	code?: string; // e.g. 'EAUTH', 'ECONNECTION', 'ETIMEDOUT'
	command?: string; // SMTP command during failure
	response?: string; // Raw SMTP response
	responseCode?: number; // Numeric SMTP code (e.g. 535)
	rejected?: string[]; //Invalid recipeints addresses
}
