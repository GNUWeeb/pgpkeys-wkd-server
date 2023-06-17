import fetch from "node-fetch";

export async function fetchContent(url: URL): Promise<Content> {
    const res = await fetch(url);

    return { data: await res.text(), etag: res.headers.get("etag")! };
}

export interface Content {
    data: string;
    etag: string;
}
