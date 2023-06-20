import { PublicKey } from "openpgp";
import { EntryKey } from "./WKDEntryManager.js";

export interface PubKey {
    data: PublicKey;
    etag: string;
}

export class PubKeySet extends Set<PubKey> {
    public constructor(pubKeys: PubKey[], public entry: EntryKey) { super(pubKeys); }

    public get(fingerprint: string): PubKey | undefined {
        for (const pubKey of this) {
            if (pubKey.data.getFingerprint().toUpperCase() === fingerprint.toUpperCase()) return pubKey;
        }
        return undefined;
    }

    public hasFingerprint(fingerprint: string): boolean { return this.get(fingerprint) !== undefined; }

    public deleteFingerprint(fingerprint: string): PubKey | undefined {
        const pubkey = this.get(fingerprint)!;
        this.delete(pubkey);
        return pubkey;
    }

    public toArray(): PubKey[] { return Array.from(this); }

    public map<T>(fn: (pubKey: PubKey) => T): T[] { return this.toArray().map(fn); }

    // Concatenates all the pubkeys into a single binary buffer
    public combineBinary(): Buffer {
        return Buffer.concat(
            this.toArray()
                .sort((a, b) => b.data.getCreationTime().getTime() - a.data.getCreationTime().getTime())
                .map(k => k.data.toPacketList().write())
        );
    }
}
