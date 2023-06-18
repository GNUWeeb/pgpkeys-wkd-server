import "dotenv/config";

export const host = process.env.HOST ?? "0.0.0.0";
export const port = Number(process.env.PORT ?? 3000);
export const repository = process.env.REPOSITORY ?? "GNUWeeb/pgpkeys";
export const branch = process.env.BRANCH ?? "master";
export const emailDomain = process.env.EMAIL_DOMAIN ?? "gnuweeb.org";

export const mapItemRegex = /^U: (?<UID>.+)\nW: (?<wkdHash>.+)\n(?<pubKeyFiles>(?<pubKeyFile>P: .+\n)*)/gm;
export const emailRegex = new RegExp(`\\b[A-Za-z0-9._%+-]+@${emailDomain}\\b`);
export const pubKeyEntry = "P: ";
