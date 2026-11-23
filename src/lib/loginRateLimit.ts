import { NextRequest } from "next/server";
import { loginAttemptModel } from "@/models/loginAttempt.model";

// Fixed-window limit on login requests per IP. Stored in Mongo (not memory)
// because serverless instances don't share memory.
export const MAX_REQUESTS = 10;
export const WINDOW_MS = 1000;

export function getClientIp(request: NextRequest): string {
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) return forwarded.split(",")[0].trim();
    return request.headers.get("x-real-ip") ?? request.ip ?? "unknown";
}

/**
 * Counts this request against the IP's current window.
 * Returns seconds until retry is allowed if over the limit, else null.
 */
export async function hitLoginRateLimit(ip: string): Promise<number | null> {
    const key = `ip:${ip}`;
    const now = new Date();

    // Bump the counter inside a live window.
    const current = await loginAttemptModel.findOneAndUpdate(
        { key, expiresAt: { $gt: now } },
        { $inc: { count: 1 } },
        { new: true },
    );

    if (current) {
        if (current.count <= MAX_REQUESTS) return null;
        return Math.max(1, Math.ceil((current.expiresAt.getTime() - now.getTime()) / 1000));
    }

    // No live window (none yet, or expired but not yet swept by TTL): start a new one.
    try {
        await loginAttemptModel.updateOne(
            { key },
            { $set: { count: 1, expiresAt: new Date(now.getTime() + WINDOW_MS) } },
            { upsert: true },
        );
    } catch (error) {
        // Concurrent upsert lost the unique-key race; the other request created the window.
        if ((error as { code?: number }).code !== 11000) throw error;
        await loginAttemptModel.updateOne({ key }, { $inc: { count: 1 } });
    }
    return null;
}
