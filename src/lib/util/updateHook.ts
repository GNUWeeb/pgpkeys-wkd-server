import { FastifyReply, FastifyRequest } from "fastify";
import { verifySignature } from "./verifySignature.js";
import { PushEvent } from "@octokit/webhooks-types";
import { branch, emailRegex, webhookSecret } from "../../constants.js";
import { WKDEntryManager } from "../WKDEntryManager.js";

function filterKeyFiles(files: string[]): string[] {
    return files
        .filter(f => f.startsWith("keys/"))
        .map(f => f.substring("keys/".length))
        .map(f => f.replace(/\.asc$/, ""));
}

export function updateHook(req: FastifyRequest, res: FastifyReply, wkd: WKDEntryManager): any {
    const { body, headers } = req as { body: PushEvent; headers: Record<string, string> };
    const { commits, ref } = body;

    // Check request headers and validity of the signature
    if (headers["content-type"] !== "application/json") return res.status(400).send({ ok: false, error: "Not JSON" });
    if (headers["x-github-event"] !== "push") return res.status(400).send({ ok: false, error: "Not a push event" });
    if (!headers["x-github-delivery"]) return res.status(400).send({ ok: false, error: "No delivery ID" });
    if (!headers["x-hub-signature-256"]) return res.status(401).send({ ok: false, error: "No signature" });

    const validity = verifySignature(webhookSecret, JSON.stringify(body), headers["x-hub-signature-256"]);
    if (!validity) return res.status(401).send({ ok: false, error: "Invalid signature" });

    // Check if the push is to the correct branch
    if (ref !== `refs/heads/${branch}`) return res.status(400).send({ ok: false, error: "Not the correct branch" });

    // Get removed and modified keys
    const toRemove = filterKeyFiles(commits.flatMap(({ removed }) => removed));
    const toModify = filterKeyFiles(commits.flatMap(({ modified }) => modified));

    if (toRemove.length > 0) {
        const removed = toRemove.reduce<{ U: string | undefined; F: string }[]>((acc, f) => {
            const pubkey = wkd.deletePubKey(f);
            if (pubkey) {
                const user = pubkey.data.users.find(({ userID }) => emailRegex.test(userID?.email ?? ""))?.userID?.userID;
                acc.push({ U: user, F: pubkey.data.getFingerprint().toUpperCase() });
            }
            return acc;
        }, []);

        if (removed.length === 0) return { ok: true, action: null };

        req.log.info({ removed }, `Removed keys, now it's ${wkd.pubKeySize} keys of ${wkd.size} WKD entries`);

        return { ok: true, action: "remove", keys: removed };
    }

    if (toModify.some(f => !wkd.hasPubKey(f))) {
        // TODO: Do modify
    }

    if (commits.some(({ modified }) => modified.includes("map.txt"))) {
        // TODO: Do full update
    }

    return { ok: true, action: null };
}
