import "dotenv/config";

export const mapItemRegex = /^U: (?<UID>.+)\nW: (?<wkdHash>.+)\n(?<pubKeyFiles>(?<pubKeyFile>P: .+\n)*)/gm;
export const emailRegex = /\b[A-Za-z0-9._%+-]+@gnuweeb\.org\b/;
export const pubKeyEntry = "P: ";

export const mapFileURL = new URL(
    "https://raw.githubusercontent.com/hzmifork/pgpkeys/feat/genmap-wkd-hash/map.txt"
);
export const pubKeyURL = (pubkeyFile: string): URL => new URL(
    `https://raw.githubusercontent.com/hzmifork/pgpkeys/feat/genmap-wkd-hash/keys/${pubkeyFile}`
);

export const host = process.env.HOST ?? "0.0.0.0";
export const port = Number(process.env.PORT ?? 3000);
