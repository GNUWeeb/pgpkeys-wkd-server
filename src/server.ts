import fastify from "fastify";
import { WKDEntryManager } from "./lib/WKDEntryManager.js";
import { updateHook } from "./lib/util/updateHook.js";

export class Server {
    public fastify = fastify({ logger: true });
    public wkd = new WKDEntryManager();

    public registerRoutes(): void {
        // We currently don't handle Web Key Directory Update Protocol, so empty string is fine.
        this.fastify.get("/policy", () => "");

        this.fastify.head("/hu/:wkdHash", (req, res) => {
            const { wkdHash } = req.params as { wkdHash: string };

            if (!this.wkd.has(wkdHash)) return res.status(404).send();

            return res.status(200).send();
        });

        this.fastify.get("/hu/:wkdHash", (req, res) => {
            const { wkdHash } = req.params as { wkdHash: string };

            if (!this.wkd.has(wkdHash)) return res.status(404).send();

            const pubKeys = this.wkd.get(wkdHash)!;

            return res
                .header("Content-Type", "application/octet-stream")
                .header("X-Fingerprints", pubKeys.map(p => p.data.getFingerprint().toUpperCase()).join(","))
                .status(200)
                .send(pubKeys.combineBinary());
        });

        this.fastify.post("/internal/updateHook", (req, res) => updateHook(req, res, this.wkd));
    }

    public async start(port: number, host = "0.0.0.0"): Promise<any> {
        this.fastify.log.info("Hello! Loading keys and starting server...");

        // Load keys
        await this.wkd.loadKeys(true);
        this.fastify.log.info(`Loaded ${this.wkd.pubKeySize} keys of ${this.wkd.size} WKD entries`);

        // Start server
        await this.fastify.register(import("@fastify/compress"));
        this.registerRoutes();
        return this.fastify.listen({ port, host });
    }

    public close(): Promise<void> {
        this.fastify.log.warn("Closing server");
        return this.fastify.close();
    }
}
