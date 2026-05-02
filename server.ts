import "dotenv/config";
import { app } from "./src/app.js";
import { config } from "./src/configs/app.config.js";

app.listen(config.PORT, () => {
	console.log(`Server running on http://localhost:${config.PORT}`);
});

app.get("/", (req, res) => {
	res.send("Server is running.... ");
});
