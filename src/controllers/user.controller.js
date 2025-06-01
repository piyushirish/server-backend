//05652417185
import { asyncHandler } from "../utils/asyncHandlers.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from 'jsonwebtoken';


const generateAccessAndRefreshToken = async(userId) => {
    try {
        const user = await User.findById(userId)
        //console.log(user)
        const accessToken = user.generateAccessToken()
        //console.log(accessToken)
        const refreshToken = user.generateRefreshToken()

        user.refreshToken
         = refreshToken
        await user.save({ validateBeforeSave: false})


        return {accessToken, refreshToken}


    } catch (error) {
        console.error("Token generation error:", error);
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }
}

const registerUser = asyncHandler( async (req, res) => {
    // get user details from frontend
    // validation -  not empty
    // check if user already exists: username, email
    // check for images check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation 
    // return response

    const {fullName, email, username, password} = req.body
    //console.log("email", email);
    //console.log(req.body);

    if(
        [fullName, email, username, password].some((field)=>
        field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{username},{email}]
    })

    if(existedUser) {
        throw new ApiError(409, "user with same email and username already exists")
    }
    console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0 ){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage  = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()

    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshtoken"
    )

    if(!createdUser){
        throw new ApiError(500, "something went wrong while registering user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )

})

const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token
    // send cookie

    const { email, username, password } = req.body
    //console.log(email)
    //console.log(username)

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }
    
    // if(!username || !email){
    //     throw new ApiError(400, " username or password is required")
    // }
    const user = await User.findOne({
        $or: [{username},{email}]
    })
    //console.log(user)

    if(!user) {
        throw new ApiError(404, "user does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    //console.log(isPasswordValid)
    if(!isPasswordValid){
        throw new ApiError(401, "Invalid user password")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)
    //console.log(accessToken)
    const loddedInuser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loddedInuser, accessToken, refreshToken
            },
            "user logged in successfully"
        )
    )
})

const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {},"User logged out"))

})

const refreshAccessToken = asyncHandler(async(req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401, "unauthorized request")
    }
    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
        const user = await User.findById(decodedToken?._id)
        if(!user){
            throw new ApiError(401, "invalid refresh token")
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "referesh token is used or expired")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshToken(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken , options)
        .cookie("refreshToken", newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "access token refreshed successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "invalid refresh token" )
    }
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken
}