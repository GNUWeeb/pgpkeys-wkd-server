import { emailRegex, mapFileURL, mapItemRegex, pubKeyURL, pubKeyEntry } from "../constants.js";
import openpgp from "openpgp";
import { fetchContent } from "./util/fetchContent.js";

export class WKDEntryManager extends Map<EntryKey, Entry> {
    public async loadKeys(): Promise<void> {
        // Get pubKeys files and raw entries
        const keys = await WKDEntryManager.getKeysURL();

        for (const [entry, rawEntry] of keys.entries()) {
            // Resolve pubKeys
            const pubKeys = await Promise.all(
                rawEntry
                    .files
                    .map(url => fetchContent(url)) // Fetch the content
                    .map(async content => { // Read the key
                        const { data, etag } = await content;
                        return { etag, data: await openpgp.readKey({ armoredKey: data }) };
                    })
            );

            // Sort pubKeys by creation time (newest first)
            this.set(entry, { uid: rawEntry.uid, pubKeys: pubKeys.sort((a, b) => b.data.getCreationTime().getTime() - a.data.getCreationTime().getTime()) });
        }
    }

    public findEntryKey(fingerprint: string): EntryKey | undefined {
        for (const [entry, { pubKeys }] of this.entries()) {
            if (pubKeys.some(p => p.data.getFingerprint().toUpperCase() === fingerprint.toUpperCase())) return entry;
        }
        return undefined;
    }

    public hasFingerprint(fingerprint: string): boolean {
        return this.findEntryKey(fingerprint) !== undefined;
    }

    private static async getKeysURL(): Promise<Map<EntryKey, EntryRaw>> {
        const { data: map } = await fetchContent(mapFileURL);

        const result = new Map<EntryKey, EntryRaw>();

        let match;
        while ((match = mapItemRegex.exec(map)) !== null) {
            const { UID: uid, wkdHash: entry, pubKeyFiles } = match.groups!;

            // Filter out emails that don't match our regex
            if (!emailRegex.test(uid)) continue;

            const pubKeyFilesURL = pubKeyFiles
                .split("\n")
                .filter(Boolean) // Filter out empty strings
                .map(p => p.substring(pubKeyEntry.length)) // Remove "P: " from the start
                .map(pubKeyURL); // Convert to URL

            if (pubKeyFilesURL.length === 0) throw new Error(`No public keys found for UID ${uid} / Entry ${entry}`);

            if (result.has(entry)) {
                const data = result.get(entry)!;
                data.uid.push(entry);
                data.files.push(...pubKeyFilesURL);
                result.set(entry, data);
            } else {
                result.set(entry, { uid: [uid], files: pubKeyFilesURL });
            }
        }

        return result;
    }
}

export type EntryKey = string;
export interface EntryRaw {
    uid: string[];
    files: URL[];
}
export interface PublicKeyData {
    data: openpgp.PublicKey;
    etag: string;
}
export interface Entry {
    uid: string[];
    pubKeys: PublicKeyData[];
}
