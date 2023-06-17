import { emailRegex, mapFileURL, mapItemRegex, pubKeyURL, pubKeyEntry } from "../constants.js";
import openpgp from "openpgp";
import { fetchContent } from "./util/fetchContent.js";

export class pgpkeys extends Map<EntryKey, Entry> {
    public async loadKeys(): Promise<void> {
        const { data: map } = await fetchContent(mapFileURL);

        let match;
        while ((match = mapItemRegex.exec(map)) !== null) {
            const { UID, wkdHash: entry, pubKeyFiles } = match.groups!;

            // Filter out emails that don't match our regex
            if (!emailRegex.test(UID)) continue;

            const pubKeyFilesURL = pubKeyFiles
                .split("\n")
                .filter(Boolean) // Filter out empty strings
                .map(p => p.substring(pubKeyEntry.length)) // Remove "P: " from the start
                .map(pubKeyURL); // Convert to URL

            if (pubKeyFilesURL.length === 0) throw new Error(`No public keys found for UID ${UID} / Entry ${entry}`);

            // Resolve pubKeys
            const pubKeys = await Promise.all(
                pubKeyFilesURL
                    .map(url => fetchContent(url)) // Fetch the content
                    .map(async content => { // Read the key
                        const { data, etag } = await content;
                        return { etag, data: await openpgp.readKey({ armoredKey: data }) };
                    })
            );

            if (this.has(entry)) {
                const data = this.get(entry)!;
                data.uid.push(UID);
                // Sort by creation time (newest first)
                data.pubKeys.push(...pubKeys.sort((a, b) => b.data.getCreationTime().getTime() - a.data.getCreationTime().getTime()));
                this.set(entry, data);
            } else {
                this.set(entry, { uid: [UID], pubKeys });
            }
        }
    }

    public findEntryKey(fingerprint: string): EntryKey | undefined {
        for (const [entry, { pubKeys }] of this.entries()) {
            if (pubKeys.some(p => p.data.getFingerprint().toUpperCase() === fingerprint.toUpperCase())) return entry;
        }
        return undefined;
    }
}

export interface Entry {
    uid: string[];
    pubKeys: PublicKeyData[];
}
export type EntryKey = string;

export interface PublicKeyData {
    data: openpgp.PublicKey;
    etag: string;
}
