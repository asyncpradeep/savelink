import { NextRequest } from "next/server";
import { loginAttemptModel } from "@/models/loginAttempt.model";

// Fixed-window counters stored in Mongo (not memory) because serverless
// instances don't share memory.

// Flood protection: every login request, per IP.
export const MAX_REQUESTS = 10;
export const REQUEST_WINDOW_MS = 1000;

// Brute-force protection: failed logins, per identifier (username/email).
export const MAX_FAILED_ATTEMPTS = 10;
export const FAILURE_WINDOW_MS = 15 * 60 * 1000;

export function getClientIp(request: NextRequest): string {
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) return forwarded.split(",")[0].trim();
    return request.headers.get("x-real-ip") ?? request.ip ?? "unknown";
}

function failureKey(identifier: string): string {
    return `fail:${identifier.trim().toLowerCase()}`;
}

function secondsUntil(date: Date): number {
    return Math.max(1, Math.ceil((date.getTime() - Date.now()) / 1000));
}

/** Increments the key's counter in its live window, starting a new window if none. Returns the new count. */
async function bump(key: string, windowMs: number): Promise<{ count: number; expiresAt: Date }> {
    const now = new Date();

    const current = await loginAttemptModel.findOneAndUpdate(
        { key, expiresAt: { $gt: now } },
        { $inc: { count: 1 } },
        { new: true },
    );
    if (current) return { count: current.count, expiresAt: current.expiresAt };

    // No live window (none yet, or expired but not yet swept by TTL): start a new one.
    const expiresAt = new Date(now.getTime() + windowMs);
    try {
        await loginAttemptModel.updateOne(
            { key },
            { $set: { count: 1, expiresAt } },
            { upsert: true },
        );
    } catch (error) {
        // Concurrent upsert lost the unique-key race; the other request created the window.
        if ((error as { code?: number }).code !== 11000) throw error;
        await loginAttemptModel.updateOne({ key }, { $inc: { count: 1 } });
    }
    return { count: 1, expiresAt };
}

/**
 * Counts this request against the IP's per-second window.
 * Returns seconds until retry is allowed if over the limit, else null.
 */
export async function hitLoginRateLimit(ip: string): Promise<number | null> {
    const { count, expiresAt } = await bump(`ip:${ip}`, REQUEST_WINDOW_MS);
    return count > MAX_REQUESTS ? secondsUntil(expiresAt) : null;
}

/** Returns seconds until retry is allowed if the identifier has too many recent failures, else null. */
export async function checkFailedLogins(identifier: string): Promise<number | null> {
    const blocked = await loginAttemptModel.findOne({
        key: failureKey(identifier),
        count: { $gte: MAX_FAILED_ATTEMPTS },
        expiresAt: { $gt: new Date() },
    });
    return blocked ? secondsUntil(blocked.expiresAt) : null;
}

export async function recordFailedLogin(identifier: string): Promise<void> {
    await bump(failureKey(identifier), FAILURE_WINDOW_MS);
}

export async function clearFailedLogins(identifier: string): Promise<void> {
    await loginAttemptModel.deleteOne({ key: failureKey(identifier) });
}
