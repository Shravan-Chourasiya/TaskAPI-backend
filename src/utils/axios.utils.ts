import axios from "axios";
import { config } from "../configs/app.config.js";

const api = axios.create({
	baseURL: config.API_BASE_URL,
	withCredentials: true,
});

export default api;
