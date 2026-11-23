import { dbConnection } from "@/lib/dbconnect";
import { userModel } from "@/models/user.model";
import { signinSchema } from "@/schema/signinSchema";
import bcrypt from 'bcryptjs'
import { NextRequest, NextResponse } from "next/server";
import jwt from 'jsonwebtoken'
import { checkFailedLogins, clearFailedLogins, getClientIp, hitLoginRateLimit, recordFailedLogin } from "@/lib/loginRateLimit";

export async function POST(request:NextRequest) {
    await dbConnection();
    try {
        const body = await request.json()
        if (!body) {
            return NextResponse.json({
                success: false,
                message: "Request body is empty"
            }, { status: 400 });
        }
        
        const parsedResult = signinSchema.parse(body);

        const retryAfter = await hitLoginRateLimit(getClientIp(request));
        if (retryAfter !== null) {
            return NextResponse.json({
                success: false,
                message: "Too many login requests. Please try again shortly."
            }, { status: 429, headers: { 'Retry-After': String(retryAfter) } });
        }

        const lockedFor = await checkFailedLogins(parsedResult.identifier);
        if (lockedFor !== null) {
            return NextResponse.json({
                success: false,
                message: "Too many failed login attempts. Please try again later."
            }, { status: 429, headers: { 'Retry-After': String(lockedFor) } });
        }

        const user = await userModel.findOne({
            $or:[
                {email:parsedResult.identifier},
                {username:parsedResult.identifier}
            ]
        })

        if (!user){
            await recordFailedLogin(parsedResult.identifier);
            return NextResponse.json({
                success:false,
                message:"couldn't find  user"
            },{status:400})
        }

        const isPasswordValid = await bcrypt.compare(String(parsedResult.password),String(user.password))

        if (!isPasswordValid) {
            await recordFailedLogin(parsedResult.identifier);
            return NextResponse.json({
                message:"Invalid password"
            },{status:401})
        }

        await clearFailedLogins(parsedResult.identifier);

        const tokendata = {
            _id: user._id,
            username: user.username,
            email: user.email
         }

         const token = await jwt
         .sign(tokendata,process.env.JWT_TOKEN_SECRET??'',{expiresIn:"10d"})

        const response = NextResponse.json({
            success: true ,
            data: user,
            token:token,
            message:"logged in success",
        },{status:200})

        response.cookies.set('token',token,{
            httpOnly:true,
            sameSite:'none',
            path:'/',
            secure:true,
            maxAge: 60 * 60 * 24 * 10,
        })

        return response;

    } catch (error) {
        console.log('error while signing',error);
        return NextResponse.json({
            success:false,
            message:`Error while signing , ${error}`
        },{status:400})
    }
}
