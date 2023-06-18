import fetch from "node-fetch";

export async function fetchContent(url: string): Promise<Content | null> {
    const res = await fetch(url);

    if (!res.ok) return null;

    return { data: await res.text(), etag: res.headers.get("etag")! };
}

export interface Content {
    data: string;
    etag: string;
}
