/**
 * ctldap - ChurchTools LDAP-Wrapper 3.0
 * SMB/samba support: NT hash computation and persistent hash store.
 *
 * ChurchTools never exposes password hashes, so the NT hash (MD4 over the UTF-16LE
 * password) required for SMB/NTLM authentication is computed here whenever a user
 * performs a successful LDAP bind with their plaintext password, and persisted so
 * that samba attributes (sambaNTPassword etc.) can be served to clients like
 * Synology DSM afterwards.
 *
 * @copyright 2017-2023 Michael Lux
 * @licence GNU/GPL v3.0
 */
import fs from "fs";
import path from "path";
import crypto from "crypto";

/**
 * Pure-JS MD4 (RFC 1320). Node's crypto no longer provides MD4, since OpenSSL 3
 * moved it into the (disabled by default) legacy provider.
 * @param {Buffer} buf Message to digest
 * @return {Buffer} 16-byte digest
 */
export function md4(buf) {
  // Padding: 0x80, zeros up to length ≡ 56 (mod 64), then 64-bit LE bit length
  const padLen = (buf.length % 64) < 56 ? 56 - (buf.length % 64) : 120 - (buf.length % 64);
  const msg = Buffer.alloc(buf.length + padLen + 8);
  buf.copy(msg);
  msg[buf.length] = 0x80;
  const bitLen = buf.length * 8;
  msg.writeUInt32LE(bitLen % 0x100000000, msg.length - 8);
  msg.writeUInt32LE(Math.floor(bitLen / 0x100000000), msg.length - 4);

  const rotl = (x, s) => ((x << s) | (x >>> (32 - s))) >>> 0;
  const F = (x, y, z) => (x & y) | (~x & z);
  const G = (x, y, z) => (x & y) | (x & z) | (y & z);
  const H = (x, y, z) => x ^ y ^ z;

  let A = 0x67452301, B = 0xefcdab89, C = 0x98badcfe, D = 0x10325476;
  const X = new Array(16);
  for (let i = 0; i < msg.length; i += 64) {
    for (let j = 0; j < 16; j++) {
      X[j] = msg.readUInt32LE(i + j * 4);
    }
    let a = A, b = B, c = C, d = D;
    // Round 1
    for (let j = 0; j < 16; j += 4) {
      a = rotl((a + F(b, c, d) + X[j]) >>> 0, 3);
      d = rotl((d + F(a, b, c) + X[j + 1]) >>> 0, 7);
      c = rotl((c + F(d, a, b) + X[j + 2]) >>> 0, 11);
      b = rotl((b + F(c, d, a) + X[j + 3]) >>> 0, 19);
    }
    // Round 2
    for (let j = 0; j < 4; j++) {
      a = rotl((a + G(b, c, d) + X[j] + 0x5a827999) >>> 0, 3);
      d = rotl((d + G(a, b, c) + X[j + 4] + 0x5a827999) >>> 0, 5);
      c = rotl((c + G(d, a, b) + X[j + 8] + 0x5a827999) >>> 0, 9);
      b = rotl((b + G(c, d, a) + X[j + 12] + 0x5a827999) >>> 0, 13);
    }
    // Round 3
    const ord = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for (let j = 0; j < 16; j += 4) {
      a = rotl((a + H(b, c, d) + X[ord[j]] + 0x6ed9eba1) >>> 0, 3);
      d = rotl((d + H(a, b, c) + X[ord[j + 1]] + 0x6ed9eba1) >>> 0, 9);
      c = rotl((c + H(d, a, b) + X[ord[j + 2]] + 0x6ed9eba1) >>> 0, 11);
      b = rotl((b + H(c, d, a) + X[ord[j + 3]] + 0x6ed9eba1) >>> 0, 15);
    }
    A = (A + a) >>> 0;
    B = (B + b) >>> 0;
    C = (C + c) >>> 0;
    D = (D + d) >>> 0;
  }
  const out = Buffer.alloc(16);
  out.writeUInt32LE(A, 0);
  out.writeUInt32LE(B, 4);
  out.writeUInt32LE(C, 8);
  out.writeUInt32LE(D, 12);
  return out;
}

/**
 * Computes the NT hash of a plaintext password (MD4 over UTF-16LE),
 * in the uppercase hex format used by the sambaNTPassword attribute.
 * @param {string} password Plaintext password
 * @return {string} 32-char uppercase hex NT hash
 */
export function ntHash(password) {
  return md4(Buffer.from(password, "utf16le")).toString("hex").toUpperCase();
}

/** Placeholder samba uses for "no valid hash": authentication always fails against it. */
export const NO_HASH = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

/**
 * Persistent JSON store for per-site SMB data: the generated domain SID and the
 * NT hashes captured on successful user binds. NT hashes are password-equivalent
 * secrets, so the file is written with mode 0600 and should live on a private volume.
 */
export class SmbStore {

  /**
   * @param {string} filePath Path of the JSON store file (created on first write)
   * @param {function} onError Callback (msg, error) for logging persistence problems
   */
  constructor(filePath, onError) {
    this.filePath = filePath;
    this.onError = onError;
    this.data = { version: 1, sites: {} };
    try {
      if (fs.existsSync(filePath)) {
        this.data = JSON.parse(fs.readFileSync(filePath, { encoding: "utf8" }));
        this.data.sites = this.data.sites || {};
      }
    } catch (error) {
      this.onError(`Could not read SMB store "${filePath}", starting empty: `, error);
    }
  }

  persist() {
    try {
      const dir = path.dirname(this.filePath);
      fs.mkdirSync(dir, { recursive: true });
      // Atomic replace, so a crash mid-write cannot corrupt the store
      const tmpFile = `${this.filePath}.tmp`;
      fs.writeFileSync(tmpFile, JSON.stringify(this.data, null, 2), { encoding: "utf8", mode: 0o600 });
      fs.renameSync(tmpFile, this.filePath);
    } catch (error) {
      this.onError(`Could not persist SMB store "${this.filePath}": `, error);
    }
  }

  site(siteName) {
    let s = this.data.sites[siteName];
    if (!s) {
      s = { users: {} };
      this.data.sites[siteName] = s;
    }
    s.users = s.users || {};
    return s;
  }

  /**
   * Returns the domain SID base (S-1-5-21-x-y-z) for a site.
   * Uses the configured override if present, otherwise generates one once and persists it.
   * @param {object} site The site to get the SID base for
   * @return {string} SID base
   */
  getSiteSid(site) {
    if (site.smbSidBase) {
      return site.smbSidBase;
    }
    const s = this.site(site.name);
    if (!s.sid) {
      const sub = () => crypto.randomBytes(4).readUInt32LE(0);
      s.sid = `S-1-5-21-${sub()}-${sub()}-${sub()}`;
      this.persist();
    }
    return s.sid;
  }

  /**
   * Stores the NT hash for a user after a successful bind, if it appeared or changed.
   * @param {object} site The site the user belongs to
   * @param {string} username The (cmsUserId) username, matched case-insensitively
   * @param {string} hash Uppercase hex NT hash
   * @return {boolean} true if the stored hash was created/updated, false if unchanged
   */
  setUserHash(site, username, hash) {
    const users = this.site(site.name).users;
    const key = username.toLowerCase();
    if (users[key]?.ntHash === hash) {
      return false;
    }
    users[key] = { ntHash: hash, lastSet: Math.floor(Date.now() / 1000) };
    this.persist();
    return true;
  }

  /**
   * Looks up the stored SMB data of a user.
   * @param {object} site The site the user belongs to
   * @param {string} username The (cmsUserId) username, matched case-insensitively
   * @return {{ntHash: string, lastSet: number}|undefined} Stored hash data, if any
   */
  getUserSmb(site, username) {
    return this.site(site.name).users[username.toLowerCase()];
  }

}
