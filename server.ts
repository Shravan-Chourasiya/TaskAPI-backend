import "dotenv/config";
import { app } from "./src/app.js";
import { config } from "./src/configs/app.config.js";

app.listen(config.PORT, () => {
	// eslint-disable-next-line no-console
	console.log(`Server running on http://localhost:${config.PORT}`);
});