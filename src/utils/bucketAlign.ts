export function alignToBucket(date: Date, granularity: "5m" | "1h" | "1d"): Date {
	const d = new Date(date);
	d.setUTCSeconds(0, 0);

	if (granularity === "5m") {
		const mins = d.getUTCMinutes();
		d.setUTCMinutes(mins - (mins % 5));
	} else if (granularity === "1h") {
		d.setUTCMinutes(0);
	} else {
		d.setUTCHours(0, 0);
	}
	return d;
}

export function windowEnd(now: Date, bufferMs: number): Date {
	return new Date(now.getTime() - bufferMs);
}
