import { asyncHandler } from "../utils/asyncHandlers.js";
import {ApiError} from "../utils/ApiError.js";
import jwt from "jsonwebtoken";
import { User } from '../models/user.model.js';

 
export const verifyJWT = asyncHandler(async(req, _, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")
        //console.log("accessToken in cookies:", req.cookies?.accessToken);
        //console.log("Authorization header:", req.header("Authorization"))
    
        if(!token) throw new ApiError(401, "Unauthorzed request")
    
        const decodeToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    
        const user = await User.findById(decodeToken?._id).select("-password -refreshToken")
        if(!user) throw new ApiError(401, "Invalid access token")
    
        req.user = user;
        next()
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid access token")
    }
})

