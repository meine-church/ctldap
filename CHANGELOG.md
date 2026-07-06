# Changelog

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