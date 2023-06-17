import { emailRegex, mapFileURL, mapItemRegex, pubKeyURL } from "../consts.js";
import fetch from "node-fetch";
import openpgp from "openpgp";

export class pgpkeys {
    public map = new Map<string, MapEntry>();
    public keys = new Map<string, openpgp.PublicKey[]>();

    public async loadMap(): Promise<void> {
        const map = await fetch(mapFileURL)
            .then(res => res.text());

        let match;
        while ((match = mapItemRegex.exec(map)) !== null) {
            const { UID, wkdHash, pubKeys: pubKeys0 } = match.groups!;

            // Filter out empty strings
            const pubKeys = pubKeys0.split("\n")
                .filter(Boolean)
                .map(p => p.substring("P: ".length));

            if (pubKeys.length === 0) throw new Error(`No public keys found for UID ${UID}`);

            if (!emailRegex.test(UID)) continue;

            this.map.set(wkdHash, { uid: UID, wkdHash, pubKeys });
        }
    }

    public async loadKeys(): Promise<void> {
        for (const [wkdHash, { pubKeys: pubKeyFiles }] of this.map) {
            const pubKeys = await Promise.all(
                pubKeyFiles
                    .map(pubKeyURL)
                    .map(url => fetch(url).then(res => res.text()))
                    .map(async content => openpgp.readKey({ armoredKey: await content }))
            );

            this.keys.set(wkdHash, pubKeys);
        }
    }
}

export interface MapEntry {
    uid: string;
    wkdHash: string;
    pubKeys: string[];
}
