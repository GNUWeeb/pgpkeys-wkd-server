export const mapFileURL = new URL(
    "https://raw.githubusercontent.com/hzmifork/pgpkeys/feat/genmap-wkd-hash/map.txt"
);

export const mapItemRegex = /^U: (?<UID>.+)\nW: (?<wkdHash>.+)\n(?<pubKeys>(?<pubKeyFile>P: .+\n)*)/gm;

export const pubKeyURL = (pubkeyFile: string): URL => new URL(
    `https://raw.githubusercontent.com/hzmifork/pgpkeys/feat/genmap-wkd-hash/keys/${pubkeyFile}`
);

export const emailRegex = /\b[A-Za-z0-9._%+-]+@gnuweeb\.org\b/;
