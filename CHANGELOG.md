# Changelog

### 3.3.0
- SMB/samba support (opt-in via `SMB_ENABLED`/`smbEnabled`), so SMB shares (e.g. Synology DSM)
  work with ChurchTools accounts. ChurchTools cannot provide the NT hash required for SMB/NTLM
  authentication, so ctldap now computes it (MD4 over the UTF-16LE password) on every successful
  LDAP bind with a plaintext password and persists it in a store file (`SMB_STORE_FILE`, default
  `./data/smb-store.json`, mode 0600, docker-compose volume `ctldap-data`). Consequently, each
  user must log in once (e.g. at the DSM web GUI) — and again after every ChurchTools password
  change — before SMB access works.
  - Users additionally carry `sambaSamAccount`/`sambaIdmapEntry` with `sambaSID`,
    `sambaPrimaryGroupSID`, `sambaNTPassword`, `sambaPwdLastSet` and `sambaAcctFlags`;
    groups carry `sambaGroupMapping`/`sambaIdmapEntry` with `sambaSID` and `sambaGroupType`.
    RIDs follow samba's algorithmic scheme (uid\*2+1000 / gid\*2+1001, rid base 1000).
  - A `sambaDomainName=<SMB_DOMAIN_NAME>,o=<site>` entry (default name `WORKGROUP`, must match
    the file server's workgroup) provides the domain SID, which is generated once per site and
    persisted (override with `SMB_SID_BASE`/`smbSidBase`).
  - The subschema now also defines the served samba attributes/objectClasses, so strict clients
    recognize samba schema support.
  - The users cache is expired when a bind captures a new/changed NT hash, so SMB works right
    after the first login instead of after the cache TTL.
- Fixed a crash (`Cannot convert undefined or null to object`) when the optional
  `specialGroupMappings` section is missing from the configuration.

### 3.2.5
- Fixed a server crash (`v?.toLowerCase is not a function`) when a client sends an equality
  filter on an attribute whose value is a number (e.g. `(id=483)` matched against the virtual
  admin user, whose `id` was the number `0`). The case-insensitive equality matcher now coerces
  values to string, and the admin user's `id` is emitted as a string like every other entry.

### 3.2.4
- Searches are now authorized for any successfully authenticated connection, not just the admin
  bind. Clients like Synology DSM bind as the user and then search (to resolve the user's own
  groups) during login; the previous admin-only restriction rejected that with "Insufficient
  access rights" and broke login. Anonymous/unauthenticated connections are still rejected.

### 3.2.3
- Root DSE now advertises the real configured naming context(s) (`o=<site>`) instead of
  `o=undefined`. The Root DSE is queried with an empty base DN, so deriving `namingContexts`
  from the request produced `o=undefined`, which clients (Synology DSM) then used as the base
  DN for lookups — breaking user resolution / login.

### 3.2.2
- Fixed mixed-case attributes (`uidNumber`, `gidNumber`, `memberUid`, `objectClass`,
  `objectClasses`, `attributeTypes`, `subschemaSubentry`, …) being stripped from search
  responses. ldapjs's `SearchResponse.send()` compares the client's requested attribute list
  (original case) against lower-cased entry attribute names, so clients that request these RFC
  names in camelCase (nss-ldap / Synology DSM) received empty entries and an empty schema. A
  middleware now lower-cases the requested-attribute list, making the comparison
  case-insensitive. This was the root cause of the DSM join failure.

### 3.2.1
- Made the `cn=subschema` entry self-contained: every attribute/objectClass referenced in a
  MUST/MAY/SUP clause (`top`, `objectClass`, `cn`, `userPassword`, `description`) is now also
  defined, so strict client-side parsers (Synology DSM) no longer fail with
  "get support schema failed" / `ldap_server_not_support`.
- Added debug logging to the subschema handler (filter + requested attributes).

### 3.2.0
- Emit real RFC2307 POSIX attributes so Synology DSM works with its *Standard* profile
  (no custom attribute mapping needed):
  - Users: `uidNumber`/`gidNumber` (as strings), `loginShell`, full standard objectClass
    chain (`top`/`person`/`organizationalPerson`/`inetOrgPerson`).
  - Groups: `gidNumber`, added `top` to the objectClass list.
  - Numeric IDs are offset by `1000000` into Synology's external-LDAP ID range
    (1000000–2097151); DSM's "UID/GID shift" must stay **off**.
- Added a synthetic `churchtools-users` posixGroup as the shared POSIX primary group
  that every user's `gidNumber` references.
- Root DSE now advertises `supportedLDAPVersion: 3`.
- `gecos` is intentionally not emitted (RFC2307 IA5/ASCII constraint vs. umlaut names).

### 3.1.5
- Added a `cn=subschema` search route that serves the RFC2307 `attributeTypes` and
  `objectClasses` definitions referenced by the Root DSE `subschemaSubentry`. Without
  it, schema-validating clients (Synology DSM) reject the server (`ldap_server_not_support`).
- Added `homeDirectory` (`/home/<uid>`) to user entries to satisfy the `posixAccount`
  MUST constraint.

### 3.1.4
- Added `posixAccount` objectClass to users and `posixGroup` to groups for POSIX /
  nss-ldap compatibility (Synology DSM requires these for the domain join test).
  `uidNumber`/`gidNumber` are mapped client-side from the existing `id` attribute.

### 3.1.3
- Added `memberUid` attribute (bare usernames) to group objects for RFC2307 / nss-ldap
  compatibility (e.g. Synology DSM). `uniqueMember` is preserved unchanged.

### 3.1.2
- Changed crypto algorithms to `@node-rs/{argon2,bcrypt}`
- Minor version updates

### 3.1.1
- Introduced CookieJar pools as workaround for ChurchTools HTTP 403 bugs
- Fixed default cache lifetime in `Dockerfile`
- Fixed some debug output

### 3.1.0
- Migrated to `ldapjs` 3.0.4
- Added case-insensitive EqualityFilter.matches() implementation
(i.e. now supports **case-insensitive user & email matching,** yay!)
- Aligned case-insensitive SubstringFilter.matches() implementation with `ldapjs` 3.x
- Fixed LDAP errors when logging in with wrong credentials
- Added workaround for ChurchTools API HTTP status 403 on session expiry
- Added back options object (for TLS encryption) in `ldapjs.createServer()`
- Introduced new logging level `TRACE` for very verbose log outputs

### 3.0.2
- Fixed error due to changed ChurchTools API pagination behavior
- Keep session cookies, which gains about 100 ms speedup
- Updated `yarn`, `bcrypt` and `got`

### 3.0.1
- Fixed scope of `ldap.filters.SubstringFilter.prototype.matches` (no arrow function...)
- Updated `ldapjs` and `ldap-escape`
- Modularized project a bit

### 3.0.0
- Use new ChurchTools API (`/api`) and token-based authentication
- Supports custom LDAP `objectClass` classes for users and groups based on CT group fields
- Removed old installation instructions, now only targeting `Docker` on amd64 and arm64
- Switched config format to YAML
- Support for `argon2`-hashed LDAP admin passwords
- Use node.js 18
- Replaced deprecated `request`-related libraries with `got` library
- Use `async`/`await` instead of explicit Promises in most places
- Improved Logging
- Switched to type "module" with modern import syntax
- Cleanups

### 2.2.2
- Fixed recursion bug (GitHub issue #3)
- Logging Bugfix

### 2.2.1
- Silent release, only minor build process fix

### 2.2
- Merged multi-site extension by @hubermat
- Updated dependencies (bcrypt and ldap-escape)
- Fixed parsing of iptables setting (commenting out now respected properly)

### 2.1
- Upgraded to ldapjs 1.0.2
- Fixed wrong street mapping
- Consistent logging
- substring queries are now case insensitive
  (Was an issue in in nextcloud group sharing, for instance)

### 2.0
- adapted to built-in ChurchTools ctldap API

### 1.0.1
- re-added missing autoload code to PHP API