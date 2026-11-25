import { NextRequest, NextResponse } from "next/server";

export async function GET(request:NextRequest){
    try {

        const response = NextResponse.json(
            {
                message:"Logged out successfully",
                success:true
            }
        )

        // Must mirror the attributes login uses to set the cookie (path '/',
        // secure, sameSite 'none', no domain) so the browser actually clears
        // it. An invalid domain (a full URL) makes the attribute a no-op.
        response.cookies.set('token','',{
            httpOnly:true,
            expires:new Date(0),
            maxAge:0,
            path:'/',
            secure:true,
            sameSite:'none',
        })

        return response;

    } catch (error:any) {

        console.error('Error during logout', error);
        return NextResponse.json({ success:false, message:"Failed to log out" }, {status:500})

    }
}