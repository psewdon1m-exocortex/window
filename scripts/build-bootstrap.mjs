import fs from "node:fs";
import { createPublicKey } from "node:crypto";

const [templatePath, keyPath, outputPath, version, repository] = process.argv.slice(2);
if (!templatePath || !keyPath || !outputPath || !/^\d+\.\d+\.\d+$/.test(version ?? "") || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? "")) throw new Error("Invalid Window bootstrap arguments");
const pem = fs.readFileSync(keyPath,"utf8");
const key = createPublicKey(pem);
if (key.asymmetricKeyType !== "rsa" || key.asymmetricKeyDetails.modulusLength < 3072 || /PRIVATE KEY/.test(pem)) throw new Error("Window bootstrap requires a public RSA-3072 key");
let template = fs.readFileSync(templatePath,"utf8");
for (const [placeholder,value] of [["__WINDOW_VERSION__",version],["__WINDOW_REPOSITORY__",repository],["__WINDOW_PUBLIC_KEY_BASE64__",Buffer.from(pem).toString("base64")]]) {
  if (template.split(placeholder).length !== 2) throw new Error(`Expected exactly one ${placeholder}`);
  template = template.replace(placeholder,value);
}
if (template.includes("__WINDOW_") || /PRIVATE KEY/.test(template)) throw new Error("Unsafe Window bootstrap");
fs.writeFileSync(outputPath, template, { mode: 0o755 });
