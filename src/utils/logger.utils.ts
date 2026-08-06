import winston from "winston";

const { combine, timestamp, colorize, json, printf } = winston.format;

const isProduction = process.env.NODE_ENV === "production";

const devFormat = printf(({ level, message, timestamp }) => {
	return `${timestamp} ${level}: ${message}`;
});

export const logger = winston.createLogger({
	level: process.env.LOG_LEVEL || "info",
	format: isProduction
		? combine(timestamp(), json())
		: combine(colorize(), timestamp(), devFormat),
	transports: [new winston.transports.Console()],
});