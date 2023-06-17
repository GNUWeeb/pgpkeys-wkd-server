import "dotenv/config.js";
import { Server } from "./lib/server.js";

const server = new Server();

process
    .on("warning", warn => server.fastify.log.warn(warn, "NODE_WARN:"))
    .on("exit", code => server.fastify.log.info(`Node process exiting with code ${code}`))
    .on("SIGINT", () => server.close().then(() => process.exit(0)))
    .on("SIGTERM", () => server.close().then(() => process.exit(0)))
    .on("uncaughtException", err => {
        server.fastify.log.error(err, "Uncaught exception");
        process.exit(1);
    })
    .on("unhandledRejection", (reason: string) => {
        server.fastify.log.error(new Error(reason), "Unhandled rejection");
        process.exit(1);
    });

server.start(Number(process.env.PORT ?? 3000), process.env.HOST ?? "0.0.0.0")
    .catch(err => {
        server.fastify.log.error(err, "Error starting server");
        process.exit(1);
    });

