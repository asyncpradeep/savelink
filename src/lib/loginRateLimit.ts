import { NextRequest } from "next/server";
import { loginAttemptModel } from "@/models/loginAttempt.model";

// Fixed-window limit on failed logins. Stored in Mongo (not memory) because
// serverless instances don't share memory.
export const MAX_FAILED_ATTEMPTS = 5;
export const WINDOW_MS = 15 * 60 * 1000;

export function getClientIp(request: NextRequest): string {
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) return forwarded.split(",")[0].trim();
    return request.headers.get("x-real-ip") ?? request.ip ?? "unknown";
}

export function rateLimitKeys(ip: string, identifier?: string): string[] {
    const keys = [`ip:${ip}`];
    if (identifier) keys.push(`id:${identifier.trim().toLowerCase()}`);
    return keys;
}

/** Returns seconds until retry is allowed if any key is over the limit, else null. */
export async function checkLoginRateLimit(keys: string[]): Promise<number | null> {
    const blocked = await loginAttemptModel.findOne({
        key: { $in: keys },
        count: { $gte: MAX_FAILED_ATTEMPTS },
        expiresAt: { $gt: new Date() },
    }).sort({ expiresAt: -1 });

    if (!blocked) return null;
    return Math.max(1, Math.ceil((blocked.expiresAt.getTime() - Date.now()) / 1000));
}

export async function recordFailedLogin(keys: string[]): Promise<void> {
    const now = new Date();
    await Promise.all(keys.map(async (key) => {
        // Bump the counter inside a live window.
        const updated = await loginAttemptModel.findOneAndUpdate(
            { key, expiresAt: { $gt: now } },
            { $inc: { count: 1 } },
        );
        if (updated) return;
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
    }));
}

export async function clearFailedLogins(keys: string[]): Promise<void> {
    await loginAttemptModel.deleteMany({ key: { $in: keys } });
}
