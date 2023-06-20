import fetch from "node-fetch";

export async function fetchContent(url: string, oldEtag?: string): Promise<Content | null> {
    const res = await fetch(url, { headers: oldEtag ? { "If-None-Match": oldEtag } : undefined });
    const etag = res.headers.get("etag")!;

    // If not either 200 - OK, or 304 - Not Modified, return null
    if (![200, 304].includes(res.status)) return null;
    return { status: res.status, data: await res.text(), etag };
}

export interface Content {
    status: number;
    data: string;
    etag: string;
}
