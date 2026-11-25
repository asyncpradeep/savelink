import mongoose from "mongoose";

type connectionObject = {
    isConnected? : number
};

const connection: connectionObject = {};

export async function dbConnection() {
    try {
        if (connection.isConnected) {
            console.log("Already connected to the database");
            return;
        }
        const db = await mongoose.connect(process.env.MONGO_URI?? '');
        connection.isConnected = db.connections[0].readyState;
        console.log("Connected to the database");
    } catch (error) {
        console.error("Error connecting to the database", error);
        // Rethrow so the calling route fails fast with a clean 500 instead of
        // proceeding and throwing a confusing error on the first query.
        throw error;
    }
}