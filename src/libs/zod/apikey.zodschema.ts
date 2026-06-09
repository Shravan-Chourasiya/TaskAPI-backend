import * as z from "zod";

export const apiKeyCreationSchema=z.object({
    name:z.string().min(5).max(30),
    description:z.string().min(10).max(300),
    env:z.enum(["production","development","test"]),
    scopes:z.array(z.string()),
    allowedIPs:z.array(z.string())
})

export const updateApiKeySchema=z.object({
    keyId:z.string(),
    keyUpdatesDetails:z.object({
        name:z.string().min(5).max(30).optional(),
        description:z.string().min(10).max(300).optional(),
        env:z.enum(["production", "development", "test"]).optional(),
        scopes:z.array(z.string()).optional(),
        allowedIPs:z.array(z.string()).optional(),
        keyStatus:z.enum(["active","inactive","revoked"]).optional()
    })
})

export const updateApiNameSchema=z.object({
    keyId:z.string(),
    newName:z.string().min(5).max(30)
})  

export const updateApiScopesSchema=z.object({
    keyId:z.string(),
    newScopes:z.array(z.string())
})

export const updateApiIPWhiteListSchema=z.object({ 
    keyId:z.string(),
    newIPs:z.array(z.string())
})