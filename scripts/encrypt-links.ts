/**
 * One-off backfill: encrypt plaintext `link` URLs in the links collection.
 *
 * Needs MONGO_URI and LINK_ENC_KEY in the environment. LINK_ENC_KEY must be the
 * same key the deployed app uses, or encrypted links can't be read.
 *
 * Before each batch is written, the original {_id, link} values are appended to
 * a local backup file (links-backup-<timestamp>.jsonl, gitignored). It holds
 * plaintext URLs: keep it until the deploy is verified, then delete it.
 *
 *   DRY_RUN=1 bun scripts/encrypt-links.ts       # report only, no writes
 *   bun scripts/encrypt-links.ts                 # encrypt
 *   START_AFTER=<id> bun scripts/encrypt-links.ts  # resume after a given _id
 *   VERIFY=1 bun scripts/encrypt-links.ts        # count remaining plaintext links
 *
 * Safe to re-run: already-encrypted links are skipped.
 */
import { appendFileSync } from "node:fs";
import mongoose from "mongoose";
import { decryptLink, encryptLink, isEncrypted } from "../src/lib/linkCrypto";

const BATCH_SIZE = Number(process.env.BATCH_SIZE ?? 100);
const DRY_RUN = process.env.DRY_RUN === "1";
const VERIFY = process.env.VERIFY === "1";
const BACKUP_FILE = process.env.BACKUP_FILE ?? `links-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;

type LinkDoc = { _id: mongoose.Types.ObjectId; link: unknown };

async function main() {
    const uri = process.env.MONGO_URI;
    if (!uri) throw new Error("MONGO_URI is not set");
    // Fail fast on a bad/missing key before touching any data.
    encryptLink("key-check");

    await mongoose.connect(uri);
    const links = mongoose.connection.collection<LinkDoc>("links");

    if (VERIFY) {
        const total = await links.countDocuments();
        const plaintext = await links.countDocuments({ link: { $not: /^enc:v1:/ } });
        console.log(`total=${total} plaintext=${plaintext} encrypted=${total - plaintext}`);
        return;
    }

    let lastId = process.env.START_AFTER ? new mongoose.Types.ObjectId(process.env.START_AFTER) : null;
    let scanned = 0, encrypted = 0, skipped = 0, conflicts = 0;

    console.log(`${DRY_RUN ? "[dry run] " : ""}batch=${BATCH_SIZE} startAfter=${lastId ?? "beginning"}${DRY_RUN ? "" : ` backup=${BACKUP_FILE}`}`);

    for (;;) {
        // Keyset pagination: stable and fast even while we update the docs we're paging over.
        const docs = await links
            .find(lastId ? { _id: { $gt: lastId } } : {}, { projection: { link: 1 } })
            .sort({ _id: 1 })
            .limit(BATCH_SIZE)
            .toArray();
        if (docs.length === 0) break;

        const ops = [];
        const originals: string[] = [];
        for (const doc of docs) {
            if (typeof doc.link !== "string" || isEncrypted(doc.link)) {
                skipped++;
                continue;
            }
            const enc = encryptLink(doc.link);
            // Round-trip check before writing anything.
            if (decryptLink(enc) !== doc.link) throw new Error(`Round-trip failed for ${doc._id}`);
            originals.push(JSON.stringify({ _id: doc._id.toString(), link: doc.link }));
            ops.push({
                updateOne: {
                    // Only write if the value is still what we read (guards concurrent changes).
                    filter: { _id: doc._id, link: doc.link },
                    update: { $set: { link: enc } },
                },
            });
        }

        if (ops.length > 0 && !DRY_RUN) {
            // Back up originals before overwriting them.
            appendFileSync(BACKUP_FILE, originals.join("\n") + "\n");
            const result = await links.bulkWrite(ops, { ordered: false });
            encrypted += result.modifiedCount;
            conflicts += ops.length - result.modifiedCount;
        } else {
            encrypted += ops.length;
        }

        scanned += docs.length;
        lastId = docs[docs.length - 1]._id;
        console.log(`through _id=${lastId}  scanned=${scanned} encrypted=${encrypted} skipped=${skipped} conflicts=${conflicts}`);
    }

    console.log(`${DRY_RUN ? "[dry run] would have encrypted" : "done, encrypted"} ${encrypted}; skipped ${skipped}; conflicts ${conflicts}`);
    if (conflicts > 0) console.log("Conflicts were changed mid-run; re-run the script to pick them up.");
}

main()
    .catch((err) => {
        console.error(err);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
