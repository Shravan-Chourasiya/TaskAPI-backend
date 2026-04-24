export interface NodemailerError extends Error {
	code?: string; // e.g. 'EAUTH', 'ECONNECTION', 'ETIMEDOUT'
	command?: string; // SMTP command during failure
	response?: string; // Raw SMTP response
	responseCode?: number; // Numeric SMTP code (e.g. 535)
	rejected?: string[]; //Invalid recipeints addresses
}
