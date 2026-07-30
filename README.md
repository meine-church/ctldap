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
ChurchTools names are not always valid LDAP names, so ctldap normalizes them:

- **Brackets** (`(`, `)`, `[`, `]`, `{`, `}`, `<`, `>`) are removed from group names and
  usernames, since parentheses delimit LDAP search filter expressions and entries containing
  them cannot be looked up reliably (e.g. `Worship (LeiterIn)` → `cn=Worship LeiterIn`).
  Leftover double spaces are collapsed. The unchanged ChurchTools group name remains available
  as the group's `displayname`, and binds are still authenticated with the original
  ChurchTools username.
- **Login names** (`uid`, `memberUid`) are additionally transliterated to ASCII
  (`mbösiger` → `mboesiger`), as required by POSIX/nss clients such as Synology DSM.

Names that become ambiguous through this normalization are reported as warnings in the log.

# Restricting synced groups & recursive members (group tags)
By default, all groups of the supported group types are provided as LDAP groups. Two optional
env vars restrict/extend this via ChurchTools group tags (list your tags and their IDs via
`GET https://<your-instance>/api/tags/group`):

- `GROUP_SYNC_TAG_IDS`: comma-separated list of group tag IDs. If set, only groups carrying at
  least one of these tags become LDAP groups; memberships in all other groups are not visible
  via LDAP. Users are not filtered by this option.
- `GROUP_SYNC_TAG_IDS_LEADERSONLY`: comma-separated list of group tag IDs. A group carrying one
  of these tags is provided as an *additional* LDAP group containing only the members with a
  leader role (ChurchTools group type roles marked as "leader"). The leaders-only group is named
  after the original group plus the suffix from `GROUP_SYNC_LEADERS_ONLY_SUFFIX` (default
  `LeiterIn`, separated by a space), e.g. `Worship` → `Worship LeiterIn`. A group may carry
  a `GROUP_SYNC_TAG_IDS` tag (regular group), one of these tags (leaders-only group only) or
  both tags (both LDAP groups are provided). A group tagged for recursive member collection
  provides the leaders of its entire subgroup subtree in its leaders-only group.
- `RECURSIVE_MEMBERS_TAG_ID`: a single group tag ID. A group carrying this tag provides not
  only its direct members, but the members of all its subgroups (the entire subtree of the
  ChurchTools group hierarchy) as LDAP group members. This is useful for clients without
  nested-group support, e.g. for Synology DSM shared folder permissions. Subgroups contribute
  their members even if they are excluded by `GROUP_SYNC_TAG_IDS` themselves - they just don't
  appear as own LDAP groups.

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
  remains the ChurchTools username; it must never be an email, since an `@` inside the
  account name breaks DSM's name resolution. Emails shared by multiple persons are dropped.
- Every user must **log in once** (e.g. at the DSM web GUI or any other service doing LDAP binds
  through ctldap) before SMB access works — and once again after each ChurchTools password change.
- The store file contains NT hashes, which are **password-equivalent** secrets: keep the
  file/volume private and treat backups of it like a password database.