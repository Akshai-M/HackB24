// import { asyncHandler } from "../utils/asyncHandler.js";
// import { ApiError } from "../utils/ApiError.js"
// import { User } from "../models/user.model.js"
// import { ApiResponse } from "../utils/ApiResponse.js";
// import zod from "zod";
// import jwt from "jsonwebtoken";

const cookieOptions = {
    secure: process.env.NODE_ENV === 'development' ? true : false,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    httpOnly: true,
    secure: true
}


export {
    registerUser,
    loginUser,
    logoutUser,
    changePassword,
    getCurrentUser
}