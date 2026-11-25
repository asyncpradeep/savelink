import { verifyToken } from "@/lib/authJWT";
import { dbConnection } from "@/lib/dbconnect";
import { LinkModel } from "@/models/link.model";
import { userModel } from "@/models/user.model";
import { NextRequest, NextResponse } from "next/server";



export async function POST(request:NextRequest) {
    await dbConnection();
     try {
        const token = await verifyToken(request);
        if (!token) {
            return NextResponse.json({
                success: false,
                message: "Invalid token"
            }, { status: 401 });
        }

        const { _id } = token.payload;
        const {link_id} = await request.json();

        if (!link_id) {
            return NextResponse.json({   
                    success: false, 
                    message: "Invalid link" 
                }, { status: 400 });
        }
        const link = await LinkModel.findOne({
            _id:link_id,
            isDeleted:false
        })
        if (!link) {
            return NextResponse.json({
                success: false,
                message: "Link not found"
            }, { status: 404 });
        }

        // Only the owner (or an admin) may delete a link.
        const user = await userModel.findById(_id);
        const isOwner = link.user?.toString() === String(_id);
        if (!isOwner && !user?.admin) {
            return NextResponse.json({
                success: false,
                message: "You are not allowed to delete this link"
            }, { status: 403 });
        }

        link.isDeleted = true;
        await link.save()

        return NextResponse.json({
            success:true,
            message:"link deleted successfully"
        })
     } catch (error:any) {
        console.error("Error deleting link:", error);
        return NextResponse.json({ 
            success:false,
            message: "An error occurred while deleting the link" }, 
            { status: 500 });
    }
}
