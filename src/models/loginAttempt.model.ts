import mongoose, { Document, Schema } from "mongoose";

export interface LoginAttempt extends Document {
    key: string;
    count: number;
    expiresAt: Date;
}

const LoginAttemptSchema: Schema<LoginAttempt> = new Schema({
    key: {
        type: String,
        required: true,
        unique: true,
    },
    count: {
        type: Number,
        default: 0,
    },
    expiresAt: {
        type: Date,
        required: true,
        // TTL index: Mongo removes the doc once expiresAt passes (checked ~every 60s)
        index: { expires: 0 },
    },
});

export const loginAttemptModel =
    mongoose.models.LoginAttempt as mongoose.Model<LoginAttempt> ||
    mongoose.model("LoginAttempt", LoginAttemptSchema);
