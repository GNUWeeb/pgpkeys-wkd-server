import fastify from "fastify";

export class Server {
    public fastify = fastify({ logger: true });

    public async start(port: number, host = "0.0.0.0"): Promise<any> {
        await this.fastify.register(import("@fastify/compress"));
        return this.fastify.listen({ port, host });
    }

    public close(): Promise<void> {
        this.fastify.log.warn("Closing server");
        return this.fastify.close();
    }
}
