import { PublicKey } from "openpgp";

export interface PubKey {
    data: PublicKey;
    etag: string;
}

export class PubKeySet extends Set<PubKey> {
    public get(fingerprint: string): PubKey | undefined {
        for (const pubKey of this) {
            if (pubKey.data.getFingerprint().toUpperCase() === fingerprint.toUpperCase()) return pubKey;
        }
        return undefined;
    }

    public hasFingerprint(fingerprint: string): boolean {
        return this.get(fingerprint) !== undefined;
    }

    public toArray(): PubKey[] {
        return Array.from(this);
    }

    public map(fn: (pubKey: PubKey) => any): any[] {
        return this.toArray().map(fn);
    }

    // Concatenates all the pubkeys into a single binary buffer
    public combineBinary(): Buffer {
        return Buffer.concat(
            this.toArray()
                .map(p => p.data.toPacketList().write())
        );
    }
}
