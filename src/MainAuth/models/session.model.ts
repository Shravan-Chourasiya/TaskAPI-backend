import mongoose from "mongoose";
import type { SessionModel } from "../types/dbModel.interface.js";

const sessionSchema = new mongoose.Schema({
    userId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"Users",
        required:[true, "User Id is required!"]
    },
    userIP: {
        type: String,
        required: [true, "IP is required!"]
    },
    userAgents: {
        type: String,
        required: [true, "User Agents are required!"]
    },
    refreshToken:{
        type:String,
        unique:[true,"Refresh Token must be Unique."],
        required:[true,"Refresh Token is required!"]    
    },
    isRevoked:{
        type:Boolean,
        default:false
    },
    expiresAt:{
        type:Date,
        default:new Date(Date.now() + 7*24*60*60*1000)
    }
}, {
    timestamps: true
})

sessionSchema.index({ userId: 1 }); // speeds up queries by userId
// sessionSchema.index({ refreshToken: 1 }); // speeds up queries by refreshToken
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL cleanup

export const sessionModel = mongoose.model<SessionModel>("Sessions", sessionSchema)
