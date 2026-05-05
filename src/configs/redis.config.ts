
export const redisConfig={
	host: process.env.REDIS_HOST!,
	port: Number(process.env.REDIS_PORT),
	password: process.env.REDIS_PASSWORD!,
	// no tls: {} for free tier
	retryStrategy(times:number) {
		if (times > 5) {return null};
		return Math.min(times * 200, 2000);
	},
	lazyConnect: true,
	maxRetriesPerRequest: 3,
}

