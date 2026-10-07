// Preloaded into CLI test runs: any network use or file write fails loudly.
// Spawning `openclaw --version` is the only side effect the command may have.
import dns from "node:dns";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import net from "node:net";
import tls from "node:tls";

const deny = (what) =>
  function denied() {
    process.stderr.write(`GUARD-VIOLATION: ${what}\n`);
    process.exit(97);
  };

globalThis.fetch = deny("fetch");
net.connect = net.createConnection = deny("net.connect");
net.Socket.prototype.connect = deny("socket.connect");
tls.connect = deny("tls.connect");
dns.lookup = deny("dns.lookup");
for (const name of [
  "writeFileSync", "writeFile", "appendFileSync", "appendFile", "mkdirSync", "mkdir",
  "rmSync", "rm", "unlinkSync", "unlink", "renameSync", "rename", "copyFileSync", "copyFile",
  "createWriteStream", "chmodSync", "chmod", "truncateSync", "truncate", "symlinkSync", "linkSync",
  "rmdirSync", "mkdtempSync", "utimesSync", "writeSync",
]) {
  if (typeof fs[name] === "function") fs[name] = deny(`fs.${name}`);
}
for (const name of ["writeFile", "appendFile", "mkdir", "rm", "unlink", "rename", "copyFile", "chmod", "truncate", "symlink", "link", "rmdir", "mkdtemp", "utimes", "open"]) {
  if (typeof fsPromises[name] === "function") fsPromises[name] = deny(`fs/promises.${name}`);
}
// openSync is allowed only for reading.
const openSync = fs.openSync;
fs.openSync = function guardedOpen(file, flags, ...rest) {
  const numeric = typeof flags === "number" ? flags : undefined;
  const writeFlags = fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND;
  if ((numeric !== undefined && (numeric & writeFlags) !== 0) || (typeof flags === "string" && /[wa+]/.test(flags))) {
    return deny(`fs.openSync(${flags})`)();
  }
  return openSync.call(this, file, flags, ...rest);
};
