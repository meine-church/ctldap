# Changelog

### 3.7.0
- Leaders-only groups (opt-in via `GROUP_SYNC_TAG_IDS_LEADERSONLY`/`groupSyncTagIdsLeadersOnly`,
  a comma-separated list of ChurchTools group tag IDs): a group carrying one of these tags is
  provided as an *additional* LDAP group containing only the members with a leader role
  (group type roles marked as "leader" in the ChurchTools master data). The extra group is
  named after the original group plus a configurable suffix
  (`GROUP_SYNC_LEADERS_ONLY_SUFFIX`/`leadersOnlyNameSuffix`, default `(LeiterIn)`), e.g.
  `Worship` → `Worship (LeiterIn)`. A group may carry a `GROUP_SYNC_TAG_IDS` tag (regular
  group), a leaders-only tag (leaders-only group only) or both (both LDAP groups are provided).
  Groups tagged for recursive member collection provide the leaders of their entire subgroup
  subtree. Both options are also configurable per site.

### 3.6.1
- Fixed the recursive member collection failing against real ChurchTools instances:
  `GET /groups/hierarchies` validates its `limit` parameter with a maximum of 200, so the
  page size of 500 was rejected with HTTP 400 and the group sync failed with an unhelpful
  "AggregateError: All promises were rejected".
- Error logging now unwraps nested error details: got HTTP errors log status, request URL
  and the (truncated) ChurchTools response body - which carries the actual API error
  message - and AggregateErrors (e.g. from `Promise.any`) log all their contained causes.

### 3.6.0
- Tag-based group sync filter (opt-in via `GROUP_SYNC_TAG_IDS`/`groupSyncTagIds`, a comma-
  separated list of ChurchTools group tag IDs): when set, only groups carrying at least one
  of these tags are provided as LDAP groups; all other groups (and memberships in them)
  disappear from LDAP. Users are not filtered. The tag data is fetched together with the
  regular group sync (`include[]=tags`), so no additional requests are needed.
- Recursive member collection (opt-in via `RECURSIVE_MEMBERS_TAG_ID`/`recursiveMembersTagId`,
  a single group tag ID): a group carrying this tag provides not only its direct members, but
  the members of all its subgroups - the entire subtree of the ChurchTools group hierarchy
  (`GET /groups/hierarchies`, cycle-safe) - as LDAP group members. The collected persons are
  served consistently in the group's `uniqueMember`/`memberUid` and in their own `memberOf`.
  Useful for clients without nested-group support, e.g. Synology DSM shared folder permissions.
  Subgroups contribute their members even when the sync filter excludes them; they only appear
  as own LDAP groups when they match the filter themselves.
- Both options are also configurable per site. Invalid (non-numeric) tag IDs abort startup
  instead of silently syncing all groups.
- The pagination helper now keys its page-count cache by API path (previously one shared entry
  for all endpoints) and tolerates endpoints without pagination metadata.
- Fixed `SMB_SID_BASE` never being applied: `yaml-env-defaults` does not substitute `${VAR:}`
  placeholders with an *empty* default at all (not even when the variable is set), so the
  sambaDomain entry served the literal string `${SMB_SID_BASE:}` as its SID base. Optional
  env vars now use the explicit default `none` (empty env values are treated as unset, too).
  NOTE: If SMB is enabled and no `SMB_SID_BASE` is set, the served domain SID changes with
  this version - once to the generated-and-persisted one (or set `SMB_SID_BASE` explicitly).

### 3.5.1
- Login names with non-ASCII characters are now transliterated: German umlauts and ligatures
  become digraphs (`mbösiger` → `mboesiger`, ß → ss), all other diacritics are stripped to
  their base letter (ñ → n, ç → c, é → e). POSIX login names must be ASCII (`memberUid` even
  has IA5 syntax by schema), and Synology DSM cannot handle accounts with non-ASCII names -
  such users were missing from DSM entirely and appeared as undecodable base64 values in
  `memberUid`. The transliterated name is used for `uid`, `memberUid` and `homeDirectory`;
  the entry DN (and `cn`) keeps the original ChurchTools username, so binds still
  authenticate correctly against the ChurchTools API. A warning is logged if two usernames
  become ambiguous after transliteration.

### 3.5.0
- **Fixes broken DSM logins from the 3.4.x `EMAIL_LOGIN` design:** the first (canonical) `uid`
  value is the ChurchTools username again, and all email addresses of the person (any domain)
  are served as *additional* `uid` values. Synology DSM composes its account names as
  `<uid[0]>@<base DN>`, so 3.4.x - which served the email as first value - produced broken
  double-@ account names (`user@maildomain@basedn`) and broke the DSM web login. Account
  names, `memberUid` and `homeDirectory` are back to the pre-3.4 values (username-based);
  the email addresses remain resolvable for clients that look logins up via `(uid=...)`
  (SMB/samba), which allows SMB logins by email with arbitrary email domains.
  Emails shared by multiple persons are dropped from all of them.

### 3.4.1
- Important events are now logged even without `DEBUG` via a new, always-on INFO level:
  server start (incl. version and listen address), the configuration summary of each site,
  completed user/group syncs from ChurchTools ("Updated users/groups: N"), successful user
  authentications, and stored/updated SMB NT hashes. Detailed request/cache/API logging
  remains behind `DEBUG`/`TRACE`.
- Fixed a broken debug log call (missing site argument) in the admin bind fallback path.

### 3.4.0
- Email login (opt-in via `EMAIL_LOGIN`/`emailLogin`): the `uid` attribute holds the person's
  email addresses (primary email first) instead of the ChurchTools username. Clients like
  Synology DSM resolve logins - notably SMB - via `uid` and treat the first value as the
  canonical username (the DSM web login already matches the `mail` attribute by itself).
  Group entries emit the canonical login name as `memberUid`, and `homeDirectory` is derived
  from it as well. Emails shared by multiple persons are dropped from all of them, so every
  `(uid=...)` lookup stays unambiguous; persons without a (unique) email fall back to their
  ChurchTools username. The SMB NT hash lookup checks the entry's `cn` and all login names,
  covering clients that bind with the email as `cn` (ChurchTools accepts email logins on its
  API). Entry DNs (`cn=<username>`) are unchanged.

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