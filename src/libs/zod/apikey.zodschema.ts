import * as z from "zod";

export const apiKeyCreationSchema=z.object({
    name:z.string().min(5).max(30),
    description:z.string().min(10).max(300),
    env:z.enum(["production","development","test"]),
    scopes:z.array(z.string()),
    allowedIPs:z.array(z.string())
})