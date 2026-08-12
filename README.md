# ctldap 3.1.2 - LDAP Wrapper for ChurchTools

This software acts as an LDAP server for ChurchTools 3

**This software was tested in a common environment, yet no warranties of any kind!** 

# Installation
`Docker` is required to run `ctldap`, `docker compose plugin` is strongly recommended.

The old installation methods are discouraged and won't be supported any further.

## Migration from version 2.x to 3.x
Version 3.0.0 includes some breaking changes in the configuration format and some parameters.
Assuming Docker setup, the necessary adaptations are not that difficult, though.

- The `CT_USER` and `CT_PW` env vars have been replaced by `API_TOKEN`. You should remove these.
- You can also delete `LDAP_PW_BCRYPT`. The password encoding is now auto-detected.
  ctldap 3.0.0 supports plaintext, bcrypt hashes, and argon2 hashes (recommended) for your LDAP admin user.
- Specify `API_TOKEN`. You can obtain your token as follows:
  - Login with **your CT LDAP user** via https://your.ct.domain/api > `General` > `login`
  (copy the `personId` from the shown output!)
  - Fetch the token via `Person` > `/persons/{personId}/logintoken`
- Apply the typo fix on `CACHE_LIVETIME` by renaming it to `CACHE_LIFETIME_MS`.

# Usage
The LDAP DNs depend on your configuration. Let's assume the following configuration:
```
ldap_user=root
ldap_password=0a1b2c3d4e5f6g7h8i9j
ldap_base_dn=churchtools
```
For such a configuration, the
- admin DN for initial binding is `cn=root,ou=users,o=churchtools`
- password for initial binding is `0a1b2c3d4e5f6g7h8i9j`
- users are found in the organizational unit `ou=users,o=churchtools`
- groups are found in the organizational unit `ou=groups,o=churchtools`

## Names in LDAP
With `EMAIL_LOCALPART_NAMES=true` (the default), the **account name** of a person - the entry
`cn`/DN and the canonical `uid` - is the **local part of the primary email address**, e.g.
`fernando.abade@example.org` → account `fernando.abade`. The ChurchTools username remains the
fallback for persons without a primary email, and whenever the local part is not unique:
shared with another person's local part (e.g. a family email address) or colliding with
another person's ChurchTools username. Set `EMAIL_LOCALPART_NAMES=false` to always use the
ChurchTools username. Binds are authenticated against the ChurchTools API with the original
ChurchTools username in either case.

ChurchTools names are not always valid LDAP names, so ctldap normalizes them:

- **Brackets** (`(`, `)`, `[`, `]`, `{`, `}`, `<`, `>`) are removed from group names and
  account names, since parentheses delimit LDAP search filter expressions and entries containing
  them cannot be looked up reliably (e.g. `Worship (LeiterIn)` → `cn=Worship LeiterIn`).
  Leftover double spaces are collapsed. The unchanged ChurchTools group name remains available
  as the group's `displayname`, and binds are still authenticated with the original
  ChurchTools username.
- **Login names** (`uid`, `memberUid`) are additionally transliterated to ASCII
  (`mbösiger` → `mboesiger`), as required by POSIX/nss clients such as Synology DSM.

Names that become ambiguous through this normalization are reported as warnings in the log.

# Caching
By default, ctldap caches the user/group data fetched from ChurchTools for 5 minutes
(`CACHE_LIFETIME_MS`, in milliseconds). Set `CACHE_LIFETIME_MS=0` (or `off`) to **disable the
cache**: every LDAP search then fetches fresh data from ChurchTools, so changes are visible
immediately and nothing is kept in memory between requests. This is useful for clients that
cache LDAP data themselves - e.g. Synology DSM, which syncs its own LDAP copy periodically.

Note that a disabled cache means several ChurchTools API requests per LDAP search (persons,
groups, memberships, master data). Concurrent lookups belonging to the same LDAP request still
share one fetch, and the completed sync messages drop from info to debug level.

# Selecting synced groups & their members (custom group fields)
Which ChurchTools groups become LDAP groups - and which members they carry - is controlled by
custom **checkbox group fields** ("DB-Felder", defined in the ChurchTools group settings). Five
env vars name the *IDs* of these fields (list your group fields incl. their IDs via
`GET https://<your-instance>/api/fields`, category `f_group`; the IDs are resolved to the
fields' keys via the REST API on every sync):

| env var | LDAP group members | default name (group `Jugend`) |
|---|---|---|
| `GROUP_FIELD_MEMBERS` | direct members (leaders included) | `Jugend` |
| `GROUP_FIELD_MEMBERS_SUBGROUP_LEADERS` | direct members + leaders of all subgroups | `Jugend inkl. LeiterInnen untergeordneter Gruppen` |
| `GROUP_FIELD_MEMBERS_SUBGROUPS` | members of the entire subgroup subtree | `Jugend inkl. untergeordnete Gruppen` |
| `GROUP_FIELD_LEADERS` | only members with a leader role | `Jugend LeiterInnen` |
| `GROUP_FIELD_LEADERS_SUBGROUP_LEADERS` | leaders of the group and of all subgroups | `Jugend LeiterInnen inkl. untergeordnete Gruppen` |

Notes:
- **Every checked field yields an own LDAP group** - a group with all five fields checked
  becomes five LDAP groups. The "members" variant keeps the ChurchTools group name, every other
  variant appends its suffix (configurable via `GROUP_FIELD_*_SUFFIX`, separated by a space).
  `GROUP_FIELD_MEMBERS_SUFFIX` is empty by default, but may be set as well.
- As soon as at least one field ID is configured, **only** groups with a checked field become
  LDAP groups; memberships in all other groups are not visible via LDAP. Setting all five vars
  to `none` disables the filter: all groups sync with their direct members. Users are never
  filtered by these options.
- The defaults are the field IDs of our ChurchTools instance (163-175); adapt them to your
  own field IDs. A configured ID that does not exist as a group field is logged as a warning
  and never matches.
- A leader role is a ChurchTools group type role marked as "leader".
- The "subgroup" variants walk the entire subtree of the ChurchTools group hierarchy. This is
  useful for clients without nested-group support, e.g. for Synology DSM shared folder
  permissions. Subgroups contribute their members even if they don't sync themselves - they
  just don't appear as own LDAP groups.
- **IMPORTANT**: ChurchTools only serves custom group fields to users whose churchdb permission
  "security level group" covers the fields' security level (newly created fields default to the
  highest level). If the API token user lacks that level, the fields are missing from the API
  responses and *no* group syncs.

# SMB support (e.g. Synology DSM shared folders)
SMB/NTLM authentication requires the NT hash of the user's password, which ChurchTools does not
provide. With `SMB_ENABLED=true`, ctldap computes the NT hash on every successful LDAP bind with
a password, persists it in `SMB_STORE_FILE` (default `./data/smb-store.json`, in Docker backed by
the `ctldap-data` volume) and serves samba attributes (`sambaNTPassword`, `sambaSID`, ...) plus a
`sambaDomainName` entry via LDAP.

Notes:
- Set `SMB_DOMAIN_NAME` to the SMB workgroup name of your file server (default: `WORKGROUP`).
- To additionally allow logins with the ChurchTools email addresses, set `EMAIL_LOGIN=true`:
  all emails of a person (any domain) are then served as additional values of the `uid`
  attribute, which SMB/samba uses to resolve login names. The first `uid` value - the
  canonical account name, from which e.g. Synology DSM composes `<username>@<base DN>` -
  remains the account name (see "Names in LDAP"); it must never be a full email, since an
  `@` inside the account name breaks DSM's name resolution. Emails shared by multiple
  persons are dropped.
- Every user must **log in once** (e.g. at the DSM web GUI or any other service doing LDAP binds
  through ctldap) before SMB access works — and once again after each ChurchTools password change.
- The store file contains NT hashes, which are **password-equivalent** secrets: keep the
  file/volume private and treat backups of it like a password database.