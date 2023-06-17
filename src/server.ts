import fastify from "fastify";
import { pgpkeys } from "./lib/pgpkeys.js";

export class Server {
    public fastify = fastify({ logger: true });
    public pgpkeys = new pgpkeys();

    public registerRoutes(): void {
        // We currently don't handle Web Key Directory Update Protocol, so empty string is fine.
        this.fastify.get("/policy", () => "");

        this.fastify.head("/hu/:wkdHash", (req, res) => {
            const { wkdHash } = req.params as { wkdHash: string };

            if (!this.pgpkeys.has(wkdHash)) return res.status(404).send();

            return res.status(200).send();
        });

        this.fastify.get("/hu/:wkdHash", (req, res) => {
            const { wkdHash } = req.params as { wkdHash: string };

            if (!this.pgpkeys.has(wkdHash)) return res.status(404).send();

            const pubKeys = this.pgpkeys.get(wkdHash)!;

            // Concatenate all public keys into a single binary blob
            const pubKeysBinary = Buffer.concat(
                pubKeys
                    .map(p => p.toPacketList().write())
            );

            return res
                .header("Content-Type", "application/octet-stream")
                .header("X-Fingerprints", pubKeys.map(p => p.getFingerprint().toUpperCase()).join(","))
                .status(200)
                .send(pubKeysBinary);
        });
    }

    public async start(port: number, host = "0.0.0.0"): Promise<any> {
        // Load mapping and keys
        await this.pgpkeys.loadMap();
        await this.pgpkeys.loadKeys();

        const total = Array.from(this.pgpkeys.values()).reduce((acc, val) => acc + val.length, 0);
        this.fastify.log.info(`Loaded ${total} keys of ${this.pgpkeys.size} key owners from mapping`);

        await this.fastify.register(import("@fastify/compress"));

        this.registerRoutes();

        return this.fastify.listen({ port, host });
    }

    public close(): Promise<void> {
        this.fastify.log.warn("Closing server");
        return this.fastify.close();
    }
}
