export interface AppError extends Error {
	code?: string; // Nodemailer, network, JWT errors
	name: string; // Built-in JS errors (TypeError, SyntaxError)
	response?: string; // SMTP/HTTP responses
	responseCode?: number; // Numeric codes (SMTP, HTTP)
	rejected?: string[]; // Nodemailer invalid recipients
}
