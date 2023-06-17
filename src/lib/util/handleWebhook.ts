import { FastifyReply, FastifyRequest } from "fastify";
import { verifySignature } from "./verifySignature.js";
import { PushEvent } from "@octokit/webhooks-types";
import { branch, webhookSecret } from "../../constants.js";
import { WKDEntryManager } from "../WKDEntryManager.js";

function filterKeyFiles(files: string[]): string[] {
    return files
        .filter(f => f.startsWith("keys/"))
        .map(f => f.substring("keys/".length));
}

export function updateHook(req: FastifyRequest, res: FastifyReply, wkd: WKDEntryManager): any {
    const body = req.body as PushEvent;

    // Check request headers and validity of the signature
    if (req.headers["content-type"] !== "application/json") return res.status(400).send({ ok: false, error: "Not JSON" });
    if (req.headers["x-github-event"] !== "push") return res.status(400).send({ ok: false, error: "Not a push event" });
    if (!req.headers["x-github-delivery"]) return res.status(400).send({ ok: false, error: "No delivery ID" });
    if (!req.headers["x-hub-signature-256"]) return res.status(401).send({ ok: false, error: "No signature" });
    const validity = verifySignature(webhookSecret, JSON.stringify(body), req.headers["x-hub-signature-256"] as string);
    if (!validity) return res.status(401).send({ ok: false, error: "Invalid signature" });

    const { commits, ref } = body;

    // Check if the push is to the correct branch
    if (ref !== `refs/heads/${branch}`) return res.status(400).send({ ok: false, error: "Not the correct branch" });

    // Get modified, and removed keys
    const modified = filterKeyFiles(body.commits.flatMap(c => c.modified));
    const removed = filterKeyFiles(body.commits.flatMap(c => c.removed));

    if (modified.length > 0) {
        const anyKeyModified = modified.some(f => wkd.hasFingerprint(f));
        if (!anyKeyModified) return { ok: true, action: null };

        // TODO: Update key in WKD Entry
    }
    if (removed.length > 0) {
        const anyKeyRemoved = removed.some(f => wkd.hasFingerprint(f));
        if (!anyKeyRemoved) return { ok: true, action: null };

        // TODO: Remove key from WKD Entry
    }
    if (commits.some(c => c.modified.includes("map.txt"))) {
        // TODO: Do full update
    }

    return { ok: true, action: null };
}
