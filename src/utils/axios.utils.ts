import axios from "axios";
import { config } from "../configs/configs.js";

const api = axios.create({
	baseURL: config.API_BASE_URL,
	withCredentials: true,
});

export default api;
