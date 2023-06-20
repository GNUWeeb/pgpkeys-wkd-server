import { createHmac } from "crypto";

export function verifySignature(secret: string, payload: string, signature: string): boolean {
    const hmac = createHmac("sha256", secret);
    hmac.update(payload);

    const digest = hmac.digest("hex");

    return `sha256=${digest}` === signature;
}
