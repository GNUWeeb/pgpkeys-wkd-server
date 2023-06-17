import fastify from "fastify";
import { pgpkeys } from "./pgpkeys.js";

export class Server {
    public fastify = fastify({ logger: true });
    public pgpkeys = new pgpkeys();

    public async start(port: number, host = "0.0.0.0"): Promise<any> {
        // Load map and keys
        await this.pgpkeys.loadMap();
        await this.pgpkeys.loadKeys();

        await this.fastify.register(import("@fastify/compress"));
        return this.fastify.listen({ port, host });
    }

    public close(): Promise<void> {
        this.fastify.log.warn("Closing server");
        return this.fastify.close();
    }
}
