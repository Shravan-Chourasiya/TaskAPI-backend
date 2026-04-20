import "dotenv/config";
import { app } from "./src/app.js";
import { config } from "./src/MainAuth/configs/configs.js";

app.listen(config.PORT, () => {
	console.log(`Server running on http://localhost:${config.PORT}`);
});

app.get("/", (req, res) => {
	res.send("Server is running.... ");
});
