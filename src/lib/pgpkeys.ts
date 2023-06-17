import { emailRegex, mapFileURL, mapItemRegex, pubKeyURL, pubKeyEntry } from "../constants.js";
import fetch from "node-fetch";
import openpgp from "openpgp";

export class pgpkeys extends Map<string, openpgp.PublicKey[]> {
    public mapping = new Map<string, MapEntry>();

    public constructor() {
        super();
        Object.defineProperty(this, "mapping", { enumerable: false });
    }

    public async loadMap(): Promise<void> {
        const map = await fetch(mapFileURL)
            .then(res => res.text());

        let match;
        while ((match = mapItemRegex.exec(map)) !== null) {
            const { UID, wkdHash, pubKeys: pubKeys0 } = match.groups!;

            // Filter out empty strings
            const pubKeys = pubKeys0.split("\n")
                .filter(Boolean)
                .map(p => p.substring(pubKeyEntry.length));

            if (pubKeys.length === 0) throw new Error(`No public keys found for UID ${UID}`);

            // Filter out emails that don't match our regex
            if (!emailRegex.test(UID)) continue;

            if (this.mapping.has(wkdHash)) {
                const entry = this.mapping.get(wkdHash)!;
                entry.uid.push(UID);
                entry.pubKeys.push(...pubKeys);
                this.mapping.set(wkdHash, entry);
            } else {
                this.mapping.set(wkdHash, { uid: [UID], pubKeys });
            }
        }
    }

    public async loadKeys(): Promise<void> {
        for (const [wkdHash, { pubKeys: pubKeyFiles }] of this.mapping) {
            const pubKeys = await Promise.all(
                pubKeyFiles
                    .map(pubKeyURL)
                    .map(url => fetch(url).then(res => res.text()))
                    .map(async content => openpgp.readKey({ armoredKey: await content }))
            );

            if (pubKeys.length === 0) throw new Error(`No public keys found for WKD hash ${wkdHash}`);

            // Sorted by creation time, newest first
            this.set(wkdHash, pubKeys.sort((a, b) => b.getCreationTime().getTime() - a.getCreationTime().getTime()));
        }
    }
}

export interface MapEntry {
    uid: string[];
    pubKeys: string[];
}