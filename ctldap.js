/**
 * ctldap - ChurchTools LDAP-Wrapper 3.0
 * This tool requires a node.js-Server and a recent version of ChurchTools 3
 * @copyright 2017-2023 Michael Lux
 * @copyright 2019-2020 Matthias Huber
 * @copyright André Schild
 * @licence GNU/GPL v3.0
 */
import fs from "fs";
import ldapjs from "ldapjs";
import { CtldapConfig } from "./ctldap-config.js";
import { SmbStore, ntHash, NO_HASH } from "./ctldap-smb.js";
import { patchLdapjsFilters } from "./ldapjs-filter-overrides.js";
const { InsufficientAccessRightsError, InvalidCredentialsError, OtherError, parseDN } = ldapjs;

// Make some ldapjs filters case-insensitive
patchLdapjsFilters();

/**
 * Simple integer range as array, inspired by https://developer.mozilla.org
 * @param start Start integer, inclusive
 * @param end Stop integer, exclusive
 * @return {number[]} Array with number sequence
 */
const range = (start, end) => Array.from({ length: end - start }, (_, i) => start + i);

const config = new CtldapConfig();

function getIsoDate() {
  return new Date().toISOString();
}

export const logTrace = (site, msg)  => {
  if (config.trace) {
    // For lazy evaluation
    if (typeof msg === "function") {
      msg = msg()
    }
    console.log(`${getIsoDate()} [TRACE] ${site.name} - ${msg}`);
  }
}

export const logDebug = (site, msg) => {
  if (config.debug) {
    // For lazy evaluation
    if (typeof msg === "function") {
      msg = msg()
    }
    console.log(`${getIsoDate()} [DEBUG] ${site.name} - ${msg}`);
  }
}

export const logInfo = (site, msg) => {
  // For lazy evaluation
  if (typeof msg === "function") {
    msg = msg()
  }
  console.log(`${getIsoDate()} [INFO]  ${site.name} - ${msg}`);
}

export const logWarn = (site, msg) => {
  console.warn(`${getIsoDate()} [WARN]  ${site.name} - ${msg}`);
}

/**
 * Logs an error with all nested details: got HTTP errors carry the API response (status and
 * body with the actual ChurchTools error message), AggregateErrors (e.g. from Promise.any in
 * fetchAllPaginated) carry the real causes in their "errors" property - without unwrapping
 * them, the log only shows a useless "All promises were rejected".
 * @param error The error to log
 * @param {string} indent Indentation, grows with nesting depth
 */
const logErrorDetails = (error, indent) => {
  console.error(indent + error.stack.replaceAll("\n", `\n${indent}`));
  if (error.response !== undefined) {
    const body = typeof error.response.body === "string"
        ? error.response.body : JSON.stringify(error.response.body);
    console.error(`${indent}HTTP ${error.response.statusCode} from ${error.response.requestUrl}: ` +
        `${body ? body.slice(0, 500) : "<empty body>"}`);
  }
  if (Array.isArray(error.errors)) {
    error.errors.forEach((nested) => logErrorDetails(nested, `${indent}  `));
  }
};

export const logError = (site, msg, error) => {
  console.error(`${getIsoDate()} [ERROR] ${site.name} - ${msg}`);
  if (error !== undefined) {
    logErrorDetails(error, "");
  }
}

logDebug({ name: 'root logger' }, "Debug mode enabled, expect lots of output!");

let options = {};
if (config.ldapCertFilename && config.ldapKeyFilename) {
  const ldapCert = fs.readFileSync(new URL(`./${config.ldapCertFilename}`, import.meta.url), { encoding: "utf8" }),
      ldapKey = fs.readFileSync(new URL(`./${config.ldapKeyFilename}`, import.meta.url), { encoding: "utf8" });
  options = { certificate: ldapCert, key: ldapKey };
}
const server = ldapjs.createServer(options);

const USERS_KEY = 'users', GROUPS_KEY = 'groups', RAW_DATA_KEY = 'rawData';

// Synology DSM places external-LDAP users/groups in the numeric ID range 1000000-2097151 and
// ignores entries outside it (lower IDs are treated as reserved system accounts). Offset the
// ChurchTools IDs into that band so DSM accepts them with its "UID/GID shift" option left OFF.
// See https://kb.synology.com/en-us/DSM/tutorial/UID_GID_reserved_by_Synology
const POSIX_ID_BASE = 1000000;
// Fixed primary group that every user's gidNumber points to (implicit POSIX primary group).
// The base value itself collides with no real group, since ChurchTools IDs start at 1.
const PRIMARY_GID = POSIX_ID_BASE;
const PRIMARY_GROUP_CN = "churchtools-users";
// LDAP group variants, each marked by an own ChurchTools checkbox group field (see
// site.groupSyncFields): EVERY checked field yields an own LDAP group, so a group with all
// five fields checked becomes five LDAP groups. The "members" variant keeps the ChurchTools
// group's name and ID; the other variants are synthetic entries named with the variant's
// suffix (site.groupVariantSuffixes) and use the source group's ID plus the variant's offset,
// keeping gidNumber/nsUniqueId unique while staying well inside Synology's accepted band
// (POSIX_ID_BASE + offset + <CT group ID> <= 2097151).
const GROUP_VARIANT_OFFSETS = {
  // The group's direct members (leaders included)
  members: 0,
  // Only the members with a leader role (offset unchanged since the 3.7 leaders-only groups)
  leaders: 500000,
  // The direct members plus the leaders of the entire subgroup subtree
  membersSubgroupLeaders: 600000,
  // The members of the entire subgroup subtree
  membersSubgroups: 700000,
  // The leaders of the group and of the entire subgroup subtree
  leadersSubgroupLeaders: 800000
};
const GROUP_VARIANT_KEYS = Object.keys(GROUP_VARIANT_OFFSETS);

// SMB/samba support: ChurchTools cannot provide the NT hash required for SMB/NTLM, so it is
// captured on each successful LDAP bind with a plaintext password (see authenticate()) and
// persisted here. User/group entries then carry samba attributes for clients like Synology DSM.
const smbStore = new SmbStore(config.smbStoreFile, (msg, error) => logError({ name: "smb store" }, msg, error));
// Samba's default algorithmic RID mapping (rid base 1000): uid*2+1000 for users, gid*2+1001 for groups.
const smbUserRid = (uidNumber) => uidNumber * 2 + 1000;
const smbGroupRid = (gidNumber) => gidNumber * 2 + 1001;

/**
 * Logs a completed ChurchTools sync: at info level with an enabled cache (a rare, meaningful
 * event), at debug level with a disabled cache (every single LDAP search syncs).
 * @param {object} site - The site the sync belongs to
 * @param {function|string} msg - The message (or a function returning it, for lazy evaluation)
 */
const logSync = (site, msg) => config.cacheDisabled ? logDebug(site, msg) : logInfo(site, msg);

/**
 * Retrieves data from cache as a Promise or refreshes the data with the provided (async) factory.
 * With a disabled cache (cacheLifetime 0), no entry is ever served or stored - but concurrent
 * requests for the same key still share the pending Promise, so one LDAP request never triggers
 * more than one ChurchTools fetch per key.
 * @param {object} site - The site for which to query the cache
 * @param {string} key - The cache key
 * @param {function} factory - A function returning a Promise that resolves with the new cache entry or rejects
 */
function getCached(site, key, factory) {
  const cache = site.CACHE;
  const co = cache[key] || { time: -1, entry: null };
  const promise = new Promise((resolve, reject) => {
    const time = new Date().getTime();
    if (!config.cacheDisabled && time - config.cacheLifetime < co.time) {
      logDebug(site, `Returning cached data for key "${key}".`);
      resolve(co.entry);
    } else {
      if (co.promise) {
        logDebug(site, `Returning pending Promise for cache key "${key}".`);
      } else {
        // Call the factory() function to retrieve the Promise for the fresh entry
        // Either resolve with the new entry (plus cache update), or pass on the rejection
        co.promise = factory().then((result) => {
          if (config.cacheDisabled) {
            // Keep no reference to the (potentially large) data set
            logDebug(site, `Cache disabled, discarding entry for cache key "${key}".`);
            co.entry = null;
            co.time = -1;
            return result;
          }
          logDebug(site, `Store cache entry for cache key "${key}".`)
          co.entry = result;
          co.time = new Date().getTime();
          return result;
        }).finally(() => {
          delete co.promise;
        });
      }
      // Wait until promise resolves
      logDebug(site, `Wait on Promise for cache key "${key}".`)
      co.promise.then(resolve, reject);
    }
  });
  cache[key] = co;
  return promise;
}

/**
 * Fetches all data from a paginated API endpoint.
 * Automatically "heals" the wrong behavior of unpatched pagination when requesting with limit of -1
 * by transparently fetching missing record(s) with another request.
 * @param {object} site The site for which this information is requested.
 * @param {string} apiPath The API endpoint to query for all paginated data.
 * @param {object} [searchParams] Additional search params (query parameters)
 */
async function fetchAllPaginated(site, apiPath, searchParams= {}) {
  // Closure for fetching a single page
  const fetchPage = (page) => {
    return site.api.get(apiPath, {
      searchParams: {
        ...searchParams,
        page
      }
    });
  };
  // Get pagination meta cache
  const pCache = site.CACHE.pagination;
  // Assume the same number of pages as last time (per API path), default to 1
  const assumedPages = pCache[apiPath] || 1;
  // Fetch assumed number of pages
  const promises = range(1, assumedPages + 1).map(fetchPage);
  // Await first result
  const firstResult = await Promise.any(promises);
  // Check first result for completeness, and fix up results and pagination cache if necessary
  // (endpoints without pagination metadata deliver everything at once)
  const nPages = firstResult['meta']?.['pagination']?.['lastPage'] ?? 1;
  if (nPages !== assumedPages) {
    logDebug(site, () => `Assumed ${assumedPages} page(s) of data for /api/${apiPath}, but had to load ${nPages}.`);
    // Update meta cache
    pCache[apiPath] = nPages;
    // Fetch remaining pages, if any
    if (nPages > assumedPages) {
      promises.push(...range(assumedPages + 1, nPages + 1).map(fetchPage));
    }
  } else {
    logDebug(site, () => `Assumed ${assumedPages} page(s) of data for /api/${apiPath}, which was correct.`);
  }
  // Await all results
  const results = await Promise.all(promises);
  // Collect all data via flatMap() and return it
  return results.flatMap(r => r['data']);
}

/**
 * Fetches all mappings of persons and groups.
 * @param {object} site The site for which this information is requested.
 */
async function fetchMemberships(site) {
  const result = await site.api.get('groups/members', {
    searchParams: {"with_deleted": false}
  });
  logDebug(site, "fetchMemberships done");
  return result['data'];
}

/**
 * Fetches all persons and computes dn values.
 * Persons are filtered by accepted invitations, because uninvited users cannot do logins anyway.
 * @param {object} site The site for which this information is requested.
 */
async function fetchPersons(site) {
  const data = await fetchAllPaginated(site, 'persons', { limit: 500 });
  logDebug(site, "fetchPersons done");
  const personMap = {};
  data.forEach((p) => {
    if (p['invitationStatus'] === "accepted" && p['cmsUserId'] && p['cmsUserId'].trim() !== "") {
      personMap[p['id']] = p;
    }
  });
  computeAccountNames(site, personMap);
  Object.values(personMap).forEach((p) => {
    // The entry name (cn) is the ASCII-transliterated account name without brackets: clients
    // like Synology DSM fail on DNs containing non-ASCII characters (e.g. umlauts).
    p.cn = ldapSafeName(site, asciiName(p.accountName), "account name");
    p.dn = site.compatTransform(site.fnUserDn(p.cn));
  });
  computeUids(site, personMap);
  return personMap;
}

/**
 * Computes the LDAP account name of each person, as p.accountName. The entry cn/DN and the
 * canonical login name (uid[0]) are derived from it.
 * With emailLocalpartNames enabled, the local part of the person's primary email address is
 * preferred, e.g. "fernando.abade@example.org" -> "fernando.abade". The ChurchTools username
 * remains the fallback for persons without a primary email - and whenever the local part
 * would be ambiguous: shared with another person's local part (case-insensitively, e.g. a
 * family email), or colliding with any other person's ChurchTools username (all usernames
 * stay reserved as fallback names, so every account name maps to exactly one person).
 * @param {object} site The site for which this information is requested.
 * @param {object} personMap Map of person id to person, each person gets "accountName" set.
 */
function computeAccountNames(site, personMap) {
  const persons = Object.values(personMap);
  if (!site.emailLocalpartNames) {
    persons.forEach((p) => p.accountName = p['cmsUserId']);
    return;
  }
  const localpartOf = (p) => {
    const email = p['email'];
    const at = typeof email === "string" ? email.indexOf("@") : -1;
    const localpart = at > 0 ? email.slice(0, at).trim() : "";
    return localpart === "" ? undefined : localpart;
  };
  // Counting is done on lowercased names, since LDAP name lookups are case-insensitive.
  const localpartCounts = {};
  persons.forEach((p) => {
    const localpart = localpartOf(p);
    if (localpart) {
      const lc = localpart.toLowerCase();
      localpartCounts[lc] = (localpartCounts[lc] || 0) + 1;
    }
  });
  const usernameOwners = {};
  persons.forEach((p) => usernameOwners[p['cmsUserId'].toLowerCase()] = p['id']);
  persons.forEach((p) => {
    const localpart = localpartOf(p);
    const lc = localpart && localpart.toLowerCase();
    if (localpart && localpartCounts[lc] === 1
        && (usernameOwners[lc] === undefined || usernameOwners[lc] === p['id'])) {
      p.accountName = localpart;
    } else {
      p.accountName = p['cmsUserId'];
      if (localpart) {
        // Debug level: shared emails (e.g. family addresses) are normal, the fallback is expected.
        logDebug(site, () => `Email local part "${localpart}" is not unique, ` +
            `keeping username "${p['cmsUserId']}" as account name`);
      }
    }
  });
}

// German umlauts/ligatures cannot be stripped to their base letter, they transliterate to digraphs.
const TRANSLIT_MAP = {
  'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'Ä': 'Ae', 'Ö': 'Oe', 'Ü': 'Ue', 'ß': 'ss',
  'æ': 'ae', 'Æ': 'Ae', 'ø': 'o', 'Ø': 'O', 'œ': 'oe', 'Œ': 'Oe'
};

/**
 * Transliterates a name used as LDAP cn/uid to ASCII: German umlauts and ligatures via
 * replacement table (ö→oe, ß→ss, ...), any other diacritics via Unicode decomposition
 * (ñ→n, ç→c, é→e, ...). POSIX/nss login and group names must be ASCII (memberUid even has
 * IA5 syntax by schema), and clients like Synology DSM cannot handle non-ASCII names at all.
 * @param {string} name The raw name, e.g. the ChurchTools username or group name
 * @return {string} The name with non-ASCII letters transliterated
 */
function asciiName(name) {
  return name.replace(/[äöüÄÖÜßæÆøØœŒ]/g, (c) => TRANSLIT_MAP[c])
      .normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

// Brackets of any kind are unusable in LDAP names: parentheses delimit search filter expressions
// (RFC 4515), so an entry whose cn/uid contains them can never be looked up by that name - clients
// (notably Synology DSM and samba) either escape them inconsistently or reject the entry outright.
const BRACKETS = /[()[\]{}<>]/g;

/**
 * Removes brackets from a name used as LDAP cn or uid and normalizes the whitespace left behind,
 * e.g. "Worship (LeiterIn)" -> "Worship LeiterIn", "mueller(2)" -> "mueller2".
 * @param {object} site The site the name belongs to, for logging.
 * @param {string} name The raw ChurchTools name (username or group name)
 * @param {string} kind What the name denotes, for logging, e.g. "group name"
 * @return {string} The name without brackets
 */
function ldapSafeName(site, name, kind) {
  const stripped = name.replace(BRACKETS, "");
  if (stripped === name) {
    // Names without brackets are passed through untouched, whitespace included.
    return name;
  }
  const safe = stripped.replace(/\s+/g, " ").trim();
  logDebug(site, () => `Removed brackets from ${kind} "${name}" -> "${safe}"`);
  return safe;
}

/**
 * Computes the login names (uid attribute values) of all persons, as p.uids.
 * The first value is always the (ASCII-transliterated) account name: clients like
 * Synology DSM treat it as the canonical account name and compose it as "<uid[0]>@<base DN>",
 * so it must never contain "@" (a full email as first value yields broken double-@ account
 * names and breaks the DSM login). It is also emitted as memberUid in group entries.
 * With emailLogin enabled, all email addresses of the person (any domain) are added as
 * additional uid values, so clients that resolve logins via (uid=...) lookups - notably
 * SMB/samba - can authenticate users by email as well. Emails shared by several persons or
 * colliding with another person's username are dropped, so every lookup stays unambiguous.
 * @param {object} site The site for which this information is requested.
 * @param {object} personMap Map of person id to person, each person gets its "uids" property set.
 */
function computeUids(site, personMap) {
  const persons = Object.values(personMap);
  // The entry DN/cn and all login names are the account name transliterated to ASCII with
  // brackets removed. Binds resolve the bound cn back to the original ChurchTools username
  // before authenticating against the API, see resolveCtUsername().
  const loginCounts = {};
  persons.forEach((p) => {
    p.login = ldapSafeName(site, asciiName(p.accountName), "login name");
    const lc = p.login.toLowerCase();
    loginCounts[lc] = (loginCounts[lc] || 0) + 1;
  });
  Object.entries(loginCounts).filter(([, count]) => count > 1).forEach(([name, count]) =>
      logWarn(site, `Login name "${name}" is ambiguous after transliteration (${count} persons)!`));
  if (!site.emailLogin) {
    persons.forEach((p) => p.uids = [p.login]);
    return;
  }
  // Email aliases: all emails of the person, the primary email first, deduplicated
  const emailsOf = (p) => {
    const seen = new Set();
    return [p['email'], ...(p['emails'] || []).map((e) => e && e['email'])].filter((e) => {
      if (typeof e !== "string" || e.trim() === "") {
        return false;
      }
      const lc = e.toLowerCase();
      return seen.has(lc) ? false : seen.add(lc);
    }).map((e) => site.compatTransformEmail(e));
  };
  // Login names are reserved, an email alias colliding with one must stay unambiguous as well.
  const emailCounts = {};
  persons.forEach((p) => {
    p.emailAliases = emailsOf(p);
    p.emailAliases.forEach((email) => {
      const lc = email.toLowerCase();
      emailCounts[lc] = (emailCounts[lc] || 0) + 1;
    });
  });
  persons.forEach((p) => {
    const unique = p.emailAliases.filter((email) => {
      const lc = email.toLowerCase();
      return emailCounts[lc] === 1 && loginCounts[lc] === undefined;
    });
    p.uids = [p.login, ...unique];
    delete p.emailAliases;
  });
}

/**
 * Returns whether a ChurchTools checkbox field is checked in a group's information object.
 * Unchecked checkboxes may be served as false/0/"0"/null - or omitted entirely.
 * @param {object} info The group's information object.
 * @param {string|undefined} fieldKey The field key, undefined when the variant is not configured.
 */
function fieldChecked(info, fieldKey) {
  if (fieldKey === undefined) {
    return false;
  }
  const val = info[fieldKey];
  return !(val === undefined || val === null || val === false
      || val === 0 || val === '' || val === '0' || val === 'false');
}

/**
 * Fetches the group field definitions (REST GET /fields) and resolves the configured group sync
 * field IDs (site.groupSyncFields) to the keys used in the groups' information objects.
 * Configured IDs without a matching group field are logged as warning and never match.
 * Only called when the custom-field-based group sync is configured.
 * @param {object} site The site for which this information is requested.
 * @return {object} The information keys by variant, unresolvable variants omitted.
 */
async function fetchGroupFieldKeys(site) {
  const result = await site.api.get('fields');
  logDebug(site, "fetchGroupFieldKeys done");
  const keysById = {};
  result['data'].filter((f) => f['fieldCategoryCode'] === 'f_group')
      .forEach((f) => keysById[Number(f['id'])] = f['key']);
  const fields = {};
  GROUP_VARIANT_KEYS.forEach((variant) => {
    const fieldId = site.groupSyncFields[variant];
    if (fieldId === undefined) {
      return;
    }
    const key = keysById[fieldId];
    if (key === undefined) {
      logWarn(site, `Group field ID ${fieldId} (variant "${variant}") does not exist as ` +
          `a group field in ChurchTools - this variant will never match!`);
    } else {
      fields[variant] = key;
    }
  });
  return fields;
}

/**
 * Fetches all groups and computes dn values and "special classes" for custom LDAP objectClass attributes.
 * With the custom-field-based group sync configured (groupSyncFields), checkbox group fields decide
 * what a group becomes: every checked field marks one LDAP group variant ("variants", see
 * GROUP_VARIANT_OFFSETS), so a group may become several LDAP groups. Groups without any checked
 * field stay in the map (variants=[]), since their memberships must remain available for the
 * recursive member collection of parent groups (see fetchAll()).
 * NOTE: ChurchTools only serves the custom fields when the API token user's group data security
 * level ("security level group") covers the fields' security level - otherwise the fields are
 * missing from the response and NO group syncs.
 * @param {object} site The site for which this information is requested.
 */
async function fetchGroups(site) {
  const [fields, data] = await Promise.all([
    // The configured field IDs are resolved to their information keys on every sync,
    // so field changes in ChurchTools are picked up without a restart.
    site.groupSyncActive ? fetchGroupFieldKeys(site) : {},
    fetchAllPaginated(site, 'groups', { limit: 100 })
  ]);
  logDebug(site, "fetchGroups done");
  const groupMap = {};
  const sgmKeys = Object.keys(site.specialGroupMappings);
  data.forEach((g) => {
    // Strip some irrelevant information
    delete g['settings'];
    delete g['roles'];
    const info = g['information'];
    // Every checked field marks one LDAP group variant. Without any configured field,
    // all groups sync as plain member groups.
    g.variants = site.groupSyncActive
        ? GROUP_VARIANT_KEYS.filter((variant) => fieldChecked(info, fields[variant]))
        : ['members'];
    // Pre-compute the LDAP entry name (cn, ASCII-transliterated with brackets removed,
    // see asciiName()) and "distinguished name"
    g.cn = ldapSafeName(site, asciiName(g['name']), "group name");
    g.dn = site.compatTransform(site.fnGroupDn(g.cn));
    g.specialClasses = sgmKeys.filter((k) => info[k])
    groupMap[g['id']] = g;
  });
  // Transliteration and bracket removal can make two group names collide (e.g. "Team (A)"
  // and "Team A", or "Bär" and "Baer"), which would yield two LDAP entries sharing one DN.
  // Only names within the same variant collide, since each variant appends its own suffix.
  const cnCounts = {};
  Object.values(groupMap).forEach((g) => g.variants.forEach((variant) => {
    const key = `${variant}:${g.cn.toLowerCase()}`;
    cnCounts[key] = (cnCounts[key] || 0) + 1;
  }));
  Object.entries(cnCounts).filter(([, count]) => count > 1).forEach(([key, count]) =>
      logWarn(site, `Group name "${key.substring(key.indexOf(':') + 1)}" is ambiguous ` +
          `after transliteration (${count} groups)!`));
  if (site.groupSyncActive) {
    const matched = Object.values(groupMap).filter((g) => g.variants.length > 0).length;
    const entries = Object.values(groupMap).reduce((n, g) => n + g.variants.length, 0);
    // Info level: makes the effect of the sync filter visible without DEBUG
    logInfo(site, () => `Group sync filter (group fields): ` +
        `${matched} of ${data.length} groups match, yielding ${entries} LDAP groups`);
  }
  return groupMap;
}

/**
 * Fetches all group hierarchies and returns a map of group ID to direct child group IDs.
 * Only called when a recursive group sync variant is configured (see groupSyncNeedsHierarchy).
 * @param {object} site The site for which this information is requested.
 */
async function fetchHierarchies(site) {
  // The hierarchies endpoint validates its limit parameter with a maximum of 200
  const data = await fetchAllPaginated(site, 'groups/hierarchies', { limit: 200 });
  logDebug(site, "fetchHierarchies done");
  const childrenMap = {};
  data.forEach((h) => childrenMap[h['groupId']] = h['children'] || []);
  return childrenMap;
}

/**
 * Fetches group types and group type roles from person master data.
 * Returns the group type names by ID and the set of role IDs marked as leader roles
 * (needed for the leaders-only groups, see the leaders group fields in groupSyncFields).
 * @param {object} site The site for which this information is requested.
 */
async function fetchMasterData(site) {
  const result = await site.api.get('person/masterdata');
  logDebug(site, "fetchMasterData done");
  const groupTypes = {};
  // noinspection JSUnresolvedFunction
  result['data']['groupTypes'].forEach((gt) => groupTypes[gt['id']] = gt['name']);
  const leaderRoleIds = new Set(
      (result['data']['roles'] || []).filter((r) => r['isLeader']).map((r) => Number(r['id'])));
  return { groupTypes, leaderRoleIds };
}

/**
 * Collects all required group and user information and computes group-to-users and user-to-groups mappings.
 * Every checked variant field yields an own LDAP group (see GROUP_VARIANT_OFFSETS), carrying the
 * member set the variant declares: the direct members, only the leaders, and/or additionally the
 * leaders or members of the entire subgroup subtree. Subgroups contribute their members even
 * when they are excluded by the sync filter themselves.
 * @param {object} site The site for which this information is requested.
 */
async function fetchAll(site) {
  return await getCached(site, RAW_DATA_KEY, async () => {
    const [personMap, allGroupMap, memberships, { groupTypes, leaderRoleIds }, childrenMap] = await Promise.all([
      fetchPersons(site), fetchGroups(site), fetchMemberships(site), fetchMasterData(site),
      // The group hierarchy is only needed for the recursive group sync variants.
      site.groupSyncNeedsHierarchy ? fetchHierarchies(site) : {}
    ]);
    if (site.groupSyncUsesLeaders && leaderRoleIds.size === 0) {
      logWarn(site, "Leaders-only groups are configured, but no group type role is marked " +
          "as leader in the ChurchTools master data - leaders-only groups will be empty!");
    }
    // Direct members (and direct leaders) per group, over ALL groups: subgroups excluded by the
    // sync filter still contribute their members to recursively collecting parent groups.
    const directMembers = {};
    const directLeaders = {};
    const addTo = (map, groupId, personId) => {
      if (!map[groupId]) {
        map[groupId] = [personId];
      } else {
        map[groupId].push(personId);
      }
    };
    memberships.forEach((m) => {
      const { personId, groupId } = m;
      // Only map persons/groups that have not been filtered
      if ((personId in personMap) && (groupId in allGroupMap)) {
        addTo(directMembers, groupId, personId);
        if (leaderRoleIds.has(Number(m['groupTypeRoleId']))) {
          addTo(directLeaders, groupId, personId);
        }
      }
    });
    // Collects the members of a group's entire subtree (the group itself, its subgroups,
    // their subgroups, ...). The visited set guards against hierarchy cycles.
    const collectSubtreeMembers = (rootId, membersOf) => {
      const members = new Set();
      const visited = new Set();
      const stack = [rootId];
      while (stack.length > 0) {
        const gid = stack.pop();
        if (visited.has(gid)) {
          continue;
        }
        visited.add(gid);
        (membersOf[gid] || []).forEach((pid) => members.add(pid));
        stack.push(...(childrenMap[gid] || []));
      }
      return [...members];
    };
    // Every checked variant yields an own LDAP group: the "members" variant keeps the
    // ChurchTools group's ID (and, without a configured suffix, its name), the other
    // variants become synthetic entries with offset IDs, named with the variant's suffix.
    const groupMap = {};
    Object.entries(allGroupMap).forEach(([id, g]) => {
      g.variants.forEach((variant) => {
        const suffix = site.groupVariantSuffixes[variant];
        if (variant === 'members' && suffix === undefined) {
          // Keeps the name, cn and dn precomputed in fetchGroups()
          g.variant = variant;
          g.sourceId = Number(id);
          groupMap[id] = g;
          return;
        }
        const name = `${g['name']} ${suffix}`;
        const cn = ldapSafeName(site, asciiName(name), "variant group name");
        groupMap[String(GROUP_VARIANT_OFFSETS[variant] + Number(id))] = {
          name,
          cn,
          information: g['information'],
          specialClasses: g.specialClasses,
          dn: site.compatTransform(site.fnGroupDn(cn)),
          variant,
          // The ChurchTools group the variant draws its members from
          sourceId: Number(id)
        };
      });
    });
    // Computes the member set of one LDAP group variant.
    const variantMembers = (variant, sourceId) => {
      switch (variant) {
        case 'leaders':
          return directLeaders[sourceId] || [];
        case 'leadersSubgroupLeaders':
          return collectSubtreeMembers(sourceId, directLeaders);
        case 'membersSubgroups':
          return collectSubtreeMembers(sourceId, directMembers);
        case 'membersSubgroupLeaders':
          // Direct members plus the leaders of the entire subtree (the group's own leaders
          // are direct members anyway, so including the root does no harm).
          return [...new Set([...(directMembers[sourceId] || []),
              ...collectSubtreeMembers(sourceId, directLeaders)])];
        default:
          return directMembers[sourceId] || [];
      }
    };
    // Create membership mappings
    const g2p = {}, p2g = {};
    Object.entries(groupMap).forEach(([id, g]) => {
      const personIds = variantMembers(g.variant, g.sourceId);
      if (g.variant !== 'members' && g.variant !== 'leaders') {
        logDebug(site, () => `Recursive members of group "${g['name']}": ` +
            `${personIds.length} total`);
      }
      if (personIds.length > 0) {
        // Entry for group-to-persons-mappings
        g2p[id] = personIds;
      }
      // Entries for person-to-groups-mappings
      personIds.forEach((personId) => {
        if (!p2g[personId]) {
          p2g[personId] = [id];
        } else {
          p2g[personId].push(id);
        }
      });
    });
    return { groupTypes, g2p, p2g, personMap, groupMap };
  });
}

/**
 * Retrieves the users for the processed request as a Promise.
 * @param {object} req - Request object
 * @param {object} _res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function requestUsers(req, _res, next) {
  const site = req.site;
  req.usersPromise = getCached(site, USERS_KEY, async () => {
    const { p2g, personMap, groupMap } = await fetchAll(site);
    const smbSid = site.smbEnabled ? smbStore.getSiteSid(site) : null;
    let newCache = Object.entries(personMap).map(([id, p]) => {
      // The cn matches the entry DN: the ASCII-transliterated account name without brackets.
      const cn = p.cn;
      const email = site.compatTransformEmail(p['email']);
      const uidNumber = POSIX_ID_BASE + Number(id);
      const attributes = {
        cn,
        displayName: `${p['firstName']} ${p['lastName']}`,
        id,
        // The login name(s), see computeUids()
        uid: p.uids,
        // POSIX numeric IDs as strings, offset into Synology's external-LDAP range (1000000-2097151).
        // Strings avoid the case-insensitive filter matcher calling .toLowerCase() on a number.
        uidNumber: String(uidNumber),
        gidNumber: String(PRIMARY_GID),
        nsUniqueId: `u${id}`,
        givenName: p['firstName'],
        street: p['street'],
        telephoneMobile: p['mobile'],
        telephoneHome: p['phonePrivate'],
        postalCode: p['zip'],
        l: p['city'],
        sn: p['lastName'],
        email,
        mail: email,
        // POSIX: posixAccount lists homeDirectory as MUST; synthesize a stable path from the login name.
        homeDirectory: `/home/${p.uids[0]}`,
        // loginShell is MAY; provide a sane default. gecos is intentionally omitted: RFC2307 defines it
        // as IA5 (ASCII), which would be violated by names containing umlauts.
        loginShell: "/bin/sh",
        objectClass: [
          'top',
          'person',
          'organizationalPerson',
          'inetOrgPerson',
          'CTPerson',
          // POSIX: nss-ldap clients (e.g. Synology DSM) require posixAccount to recognize login users.
          'posixAccount',
          // Map special CT field names of associated groups to the LDAP objectClass names defined in configuration.
          ...(p2g[id] || [])
              .flatMap((gid) => groupMap[gid].specialClasses)
              .map((key) => site.specialGroupMappings[key]['personClass'])
        ],
        memberOf: (p2g[id] || []).map((gid) => groupMap[gid].dn)
      };
      if (smbSid) {
        // The NT hash is stored under the name used in the bind DN: usually the login name (the
        // cn of the entry DN), but clients may also bind with an email alias as cn -
        // ChurchTools accepts email logins on its API.
        const smb = [...new Set([cn, ...p.uids])]
            .map((name) => smbStore.getUserSmb(site, name)).find(Boolean);
        attributes.objectClass.push('sambaSamAccount', 'sambaIdmapEntry');
        attributes.sambaSID = `${smbSid}-${smbUserRid(uidNumber)}`;
        attributes.sambaPrimaryGroupSID = `${smbSid}-${smbGroupRid(PRIMARY_GID)}`;
        attributes.sambaAcctFlags = "[U          ]";
        // Until the user's first bind with a password, no NT hash is known; the placeholder
        // makes SMB authentication fail (instead of serving no sambaNTPassword at all).
        attributes.sambaNTPassword = smb ? smb.ntHash : NO_HASH;
        attributes.sambaPwdLastSet = String(smb ? smb.lastSet : 0);
        // LM hashes are obsolete; the placeholder disables LM authentication.
        attributes.sambaLMPassword = NO_HASH;
        attributes.sambaPasswordHistory = "0".repeat(64);
      }
      return { dn: p.dn, attributes };
    });
    newCache = site.uniqueEmails(newCache);
    // Virtual admin user
    if (site.ldapPassword !== undefined) {
      const cn = site.ldapUser;
      newCache.push({
        dn: site.compatTransform(site.fnUserDn(cn)),
        attributes: {
          cn,
          displayname: "LDAP Administrator",
          // String, like every other entry's id: filter matching calls .toLowerCase() on the value.
          id: "0",
          uid: cn,
          nsUniqueId: "u0",
          givenName: "LDAP Administrator",
          objectClass: ['person'],
        }
      });
    }
    // Info level: this marks a completed user sync from ChurchTools (cache refresh). With a
    // disabled cache every search syncs, so it is logged at debug level to avoid log spam.
    logSync(site, () => `Updated users: ${newCache.length}`);
    return newCache;
  });
  return next();
}

/**
 * Retrieves the groups for the processed request as a Promise.
 * @param {object} req - Request object
 * @param {object} _res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function requestGroups(req, _res, next) {
  const site = req.site;
  req.groupsPromise = getCached(site, GROUPS_KEY, async () => {
    const { groupTypes, g2p, personMap, groupMap } = await fetchAll(site);
    const smbSid = site.smbEnabled ? smbStore.getSiteSid(site) : null;
    // Attaches the samba group attributes to a group's attributes, if SMB support is enabled.
    const withSmbAttributes = (attributes) => {
      if (smbSid) {
        attributes.objectClass.push("sambaGroupMapping", "sambaIdmapEntry");
        attributes.sambaSID = `${smbSid}-${smbGroupRid(Number(attributes.gidNumber))}`;
        // 2 = domain group
        attributes.sambaGroupType = "2";
      }
      return attributes;
    };
    const newCache = Object.entries(groupMap).map(([id, g]) => {
      // The cn matches the entry DN: the ASCII-transliterated ChurchTools group name without
      // brackets. The unchanged name stays available as displayname, which is not part of any
      // DN or filter lookup.
      const cn = g.cn;
      const info = g['information'];
      const groupType = groupTypes[info['groupTypeId']];
      const objectClasses = ["top", "group", "CTGroup" + groupType.charAt(0).toUpperCase() + groupType.slice(1),
        // POSIX: nss-ldap clients (e.g. Synology DSM) require posixGroup to resolve groups.
        "posixGroup",
        // Map observed special CT field names to the LDAP objectClass names defined in configuration.
        ...g.specialClasses.map((key) => site.specialGroupMappings[key]['groupClass'])];
      return {
        dn: g.dn,
        attributes: withSmbAttributes({
          cn,
          displayname: g['name'],
          id,
          nsUniqueId: `g${id}`,
          // POSIX numeric group ID as string, offset into Synology's external-LDAP range (1000000-2097151).
          gidNumber: String(POSIX_ID_BASE + Number(id)),
          objectClass: objectClasses,
          uniqueMember: (g2p[id] || []).map((pid) => personMap[pid].dn),
          // RFC2307 group membership: nss-ldap clients (e.g. Synology) resolve members
          // via memberUid (bare username), not uniqueMember/DNs. Must be the canonical
          // login name (first uid value), so members resolve with emailLogin enabled, too.
          memberUid: (g2p[id] || []).map((pid) => personMap[pid].uids[0])
        })
      };
    });
    // Synthetic POSIX primary group that every user's gidNumber points to. Gives DSM a resolvable
    // primary group without inventing per-user private groups; supplementary CT groups still resolve
    // via memberUid on their own entries.
    newCache.push({
      dn: site.compatTransform(site.fnGroupDn(PRIMARY_GROUP_CN)),
      attributes: withSmbAttributes({
        cn: PRIMARY_GROUP_CN,
        displayname: "ChurchTools Users",
        id: "0",
        nsUniqueId: "g0",
        gidNumber: String(PRIMARY_GID),
        objectClass: ["top", "posixGroup"]
      })
    });
    // Info level: this marks a completed group sync from ChurchTools (cache refresh). With a
    // disabled cache every search syncs, so it is logged at debug level to avoid log spam.
    logSync(site, () => `Updated groups: ${newCache.length}`);
    return newCache;
  });
  return next();
}

/**
 * Authorizes a search: the admin bind, or any connection that has completed a successful
 * authentication (see authenticate(), which sets `_ctAuthenticated` on the connection).
 * Clients such as Synology DSM bind as the user and then search (e.g. to resolve the user's
 * own groups) during login, so restricting searches to the admin bind alone breaks their login.
 * Anonymous/unauthenticated connections remain rejected.
 * @param {object} req - Request object
 * @param {object} _res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function authorize(req, _res, next) {
  const ldapConn = req.connection.ldap;
  if (ldapConn.bindDN.equals(req.site.adminDn) || ldapConn._ctAuthenticated === true) {
    return next();
  }
  logWarn(req.site, () => `Rejected search from unauthenticated bind: ${ldapConn.bindDN.toString()}`);
  return next(new InsufficientAccessRightsError());
}

/**
 * Performs debug logging if debug mode is enabled.
 * @param {object} req - Request object
 * @param {object} _res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function searchLogging(req, _res, next) {
  logDebug(req.site, () => `SEARCH base object: ${req.dn.toString()} scope: ${req.scopeName}`);
  logDebug(req.site, () => `Filter: ${req.filter.toString()}`);
  return next();
}

/**
 * Works around an ldapjs bug in SearchResponse.send(): it compares the client's requested
 * attribute list (kept in the client's original case) against lower-cased entry attribute names,
 * so any mixed-case attribute (uidNumber, gidNumber, memberUid, objectClass, objectClasses,
 * attributeTypes, subschemaSubentry, ...) is stripped from the response whenever a client
 * requests it by name in non-lowercase form (as nss-ldap clients like Synology DSM do).
 * Lower-casing the requested list makes the comparison effectively case-insensitive. This is safe:
 * LDAP attribute descriptors are case-insensitive, and the returned attribute *names* are taken
 * from the entry itself, not from this list.
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function lowerCaseRequestedAttributes(req, res, next) {
  const lowerInPlace = (arr) => {
    if (Array.isArray(arr)) {
      for (let i = 0; i < arr.length; i++) {
        if (typeof arr[i] === "string") {
          arr[i] = arr[i].toLowerCase();
        }
      }
    }
  };
  lowerInPlace(req.attributes);
  // res.attributes is what SearchResponse.send() actually consults; it may be a separate array.
  if (res && res.attributes !== req.attributes) {
    lowerInPlace(res.attributes);
  }
  return next();
}

/**
 * Evaluates req.usersPromise and sends matching elements to the client.
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function sendUsers(req, res, next) {
  req.usersPromise.then((users) => {
    users.forEach((u) => {
      if ((req.checkAll || req.dn.equals(u.dn)) && req.filter.matches(u.attributes, false)) {
        logTrace(req.site, () => `MatchUser: ${u.dn.toString()}`);
        res.send(u);
      }
    });
    return next();
  }, (error) => {
    logError(req.site, "Error whilst retrieving users: ", error);
    return next();
  });
}

/**
 * Evaluates req.groupsPromise and sends matching elements to the client.
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function sendGroups(req, res, next) {
  req.groupsPromise.then((groups) => {
    groups.forEach((g) => {
      if ((req.checkAll || req.dn.equals(g.dn)) && req.filter.matches(g.attributes, false)) {
        logTrace(req.site, () => `MatchGroup: ${g.dn}`);
        res.send(g);
      }
    });
    return next();
  }, (error) => {
    logError(req.site, "Error whilst retrieving groups: ", error);
    return next();
  });
}

/**
 * Sends the site's sambaDomain entry if it matches the search. Samba (e.g. on Synology DSM)
 * looks this entry up by its workgroup name to obtain the domain SID before authenticating
 * SMB users against their sambaNTPassword.
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function sendDomain(req, res, next) {
  const entry = req.site.smbDomainEntry;
  // DN.equals() compares attribute values case-sensitively, so normalize for base-scope reads.
  const dnMatches = () => req.dn.toString().toLowerCase() === entry.dn.toLowerCase();
  if (entry && (req.checkAll || dnMatches()) && req.filter.matches(entry.attributes, false)) {
    logTrace(req.site, () => `MatchDomain: ${entry.dn}`);
    res.send(entry);
  }
  return next();
}

/**
 * Calls the res.end() function to finalize successful chain processing.
 * @param {object} _req - Request object
 * @param {object} res - Response object
 * @param {function} next - Next handler function of filter chain
 */
function endSuccess(_req, res, next) {
  res.end();
  return next();
}

/**
 * Resolves the cn a client binds with back to the ChurchTools username. Entry cn values may
 * differ from it: they are transliterated to ASCII (see asciiName()), have brackets
 * removed (see ldapSafeName()) and may be derived from the primary email's local part (see
 * computeAccountNames()), so the ChurchTools username must be restored before it is sent to
 * the ChurchTools API. Names that match no person - the admin
 * bind, or an email alias, which ChurchTools accepts as login as well - are passed through
 * unchanged.
 * @param {object} site The site of the bind.
 * @param {string} cn The cn of the bind DN.
 * @return {Promise<string>} The ChurchTools username to authenticate with.
 */
async function resolveCtUsername(site, cn) {
  try {
    const { personMap } = await fetchAll(site);
    const lc = cn.toLowerCase();
    const person = Object.values(personMap).find((p) => p.cn.toLowerCase() === lc);
    if (person && person['cmsUserId'] !== cn) {
      logDebug(site, () => `Resolved bind name "${cn}" to ChurchTools username "${person['cmsUserId']}"`);
    }
    return person ? person['cmsUserId'] : cn;
  } catch (error) {
    // Without the person data the bind name is the best guess - it only differs for
    // usernames containing non-ASCII characters or brackets, or email-local-part account names.
    logWarn(site, `Could not resolve bind name "${cn}" against ChurchTools persons: ${error}`);
    return cn;
  }
}

/**
 * Checks the given credentials against the credentials in the config file or against the ChurchTools API.
 * @param {object} req - Request object
 * @param {object} _res - Response object
 * @param {function} next - Next handler function of filter chain
 */
async function authenticate(req, _res, next) {
  const site = req.site;
  if (req.dn === site.adminDn) {
    logDebug(site, () => `Admin bind with DN "${req.dn}"`);
    // If ldapPassword is undefined, try a default ChurchTools authentication with this user
    if (site.ldapPassword) {
      try {
        await site.authenticateAdmin(req.credentials);
        logDebug(site, "Admin bind successful");
        // Mark the connection as authenticated so subsequent searches are authorized.
        req.connection.ldap._ctAuthenticated = true;
        return next();
      } catch (error) {
        logError(site, "Invalid password for admin bind or auth error: ", error);
        return next(new InvalidCredentialsError());
      }
    } else {
      logDebug(site, "ldapPassword is undefined, trying ChurchTools authentication...")
    }
  } else {
    logDebug(site, () => `Bind user with DN "${req.dn}"`);
  }
  // The name the client binds with (the entry cn), and the ChurchTools username behind it.
  const bindName = parseDN(req.dn).rdnAt(0).getValue("cn");
  const username = await resolveCtUsername(site, bindName);
  try {
    await site.api.post('login', {
      json: {
        "username": username,
        "password": req.credentials
      }
    });
    logInfo(site, `Authentication successful for "${username}"`);
    if (site.smbEnabled) {
      // SMB/NTLM needs the NT hash of the password, which ChurchTools cannot provide.
      // Capture it from this successful plaintext bind and persist it for SMB clients.
      // Stored under the bind name, since that is what the entry lookup uses (see requestUsers()).
      if (smbStore.setUserHash(site, bindName, ntHash(req.credentials))) {
        logInfo(site, () => `Stored new SMB NT hash for "${bindName}"`);
        // Expire the users cache, so the new hash is served without waiting for the cache TTL.
        const cached = site.CACHE[USERS_KEY];
        if (cached) {
          cached.time = -1;
        }
      }
    }
    // Mark the connection as authenticated so subsequent searches are authorized.
    req.connection.ldap._ctAuthenticated = true;
    return next();
  } catch (error) {
    if (error.response?.statusCode === 400) {
      logWarn(site, `Authentication error (CT API HTTP 400) occurred for "${username}" (probably wrong password): ${error}`);
      return next(new InvalidCredentialsError());
    } else {
      logError(site, `Authentication error for "${username}": ${error}`);
      return next(new OtherError());
    }
  }
}

config.sites.forEach((site) => {
  logInfo(site, () => `Site configured: base DN "o=${site.name}", ` +
      `account names from ${site.emailLocalpartNames ? "email local part" : "ChurchTools username"}, ` +
      `email login ${site.emailLogin ? "enabled" : "disabled"}, ` +
      `SMB ${site.smbEnabled ? `enabled (domain "${site.smbDomainName}")` : "disabled"}, ` +
      `group sync ${site.groupSyncActive
          ? `by group field IDs [${GROUP_VARIANT_KEYS
              .filter((variant) => site.groupSyncFields[variant] !== undefined)
              .map((variant) => `${variant}=${site.groupSyncFields[variant]}`).join(", ")}]`
          : "unfiltered (all groups, direct members)"}`);

  // SMB: static sambaDomain entry, served by sendDomain() for searches below "o=<site>".
  // All values are strings, since the case-insensitive filter matchers expect string values.
  if (site.smbEnabled) {
    site.smbDomainEntry = {
      dn: site.compatTransform(site.fnSmbDomainDn(site.smbDomainName)),
      attributes: {
        cn: site.smbDomainName,
        sambaDomainName: site.smbDomainName,
        sambaSID: smbStore.getSiteSid(site),
        // Matches the RID scheme of smbUserRid()/smbGroupRid()
        sambaAlgorithmicRidBase: "1000",
        // Relaxed default password/lockout policies: passwords are governed by ChurchTools.
        sambaMinPwdLength: "1",
        sambaPwdHistoryLength: "0",
        sambaLogonToChgPwd: "0",
        sambaMaxPwdAge: "-1",
        sambaMinPwdAge: "0",
        sambaLockoutDuration: "30",
        sambaLockoutObservationWindow: "30",
        sambaLockoutThreshold: "0",
        sambaForceLogoff: "-1",
        sambaRefuseMachinePwdChange: "0",
        objectClass: ["top", "sambaDomain"]
      }
    };
  }

  // Login bind for user
  server.bind(`ou=users,o=${site.name}`, (req, _res, next) => {
    req.site = site;
    next();
  }, authenticate, endSuccess);

  // Search implementation for user search
  server.search(`ou=users,o=${site.name}`, (req, _res, next) => {
    req.site = site;
    next();
  }, searchLogging, authorize, lowerCaseRequestedAttributes, (req, _res, next) => {
    logDebug(site, "Search for users");
    req.checkAll = req.scopeName !== "base" && req.dn.length === 2;
    return next();
  }, requestUsers, sendUsers, endSuccess);

  // Search implementation for group search
  server.search(`ou=groups,o=${site.name}`, (req, _res, next) => {
    req.site = site;
    next();
  }, searchLogging, authorize, lowerCaseRequestedAttributes, (req, _res, next) => {
    logDebug(site, "Search for groups");
    req.checkAll = req.scopeName !== "base" && req.dn.length === 2;
    return next();
  }, requestGroups, sendGroups, endSuccess);

  // Search implementation for user and group search
  server.search(`o=${site.name}`, (req, _res, next) => {
    req.site = site;
    next();
  }, searchLogging, authorize, lowerCaseRequestedAttributes, (req, _res, next) => {
    logDebug(site, "Search for users and groups combined");
    req.checkAll = req.scopeName === "subtree";
    return next();
  }, requestUsers, requestGroups, sendUsers, sendGroups, sendDomain, endSuccess);
});

// Subschema subentry: DSM follows subschemaSubentry from the Root DSE and requires
// objectClasses + attributeTypes definitions here, otherwise it rejects the server
// ("get support schema failed", ldap_server_not_support). The schema is self-contained:
// every attribute/objectClass referenced in a MUST/MAY/SUP clause is also defined here, so
// strict client-side parsers (Synology DSM, built on OpenLDAP libs) accept it.
server.search('cn=subschema', lowerCaseRequestedAttributes, (req, res) => {
  logDebug({ name: 'subschema' }, () =>
      `Subschema request, scope: ${req.scopeName}, filter: ${req.filter.toString()}, ` +
      `attributes: ${JSON.stringify(req.attributes)}`);
  const obj = {
    dn: 'cn=subschema',
    attributes: {
      objectClass: ['top', 'subentry', 'subschema', 'extensibleObject', 'ldapSubEntry'],
      cn: 'subschema',
      attributeTypes: [
        "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
        "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
        "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.1.1.1.12 NAME 'memberUid' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
        "( 1.3.6.1.1.1.1.2 NAME 'gecos' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 1.3.6.1.1.1.1.4 NAME 'loginShell' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        // Samba 3 schema subset, so clients (Synology DSM) recognize SMB/NTLM support via LDAP
        "( 1.3.6.1.4.1.7165.2.1.20 NAME 'sambaSID' DESC 'Security ID' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.23 NAME 'sambaPrimaryGroupSID' DESC 'Primary Group Security ID' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.24 NAME 'sambaLMPassword' DESC 'LanManager Password' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.25 NAME 'sambaNTPassword' DESC 'MD4 hash of the unicode password' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.26 NAME 'sambaAcctFlags' DESC 'Account Flags' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.27 NAME 'sambaPwdLastSet' DESC 'Timestamp of the last password update' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.54 NAME 'sambaPasswordHistory' DESC 'Concatenated MD5 hashes of the salted NT passwords used on this account' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
        "( 1.3.6.1.4.1.7165.2.1.38 NAME 'sambaDomainName' DESC 'Windows NT domain to which the user belongs' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 1.3.6.1.4.1.7165.2.1.19 NAME 'sambaGroupType' DESC 'NT Group Type' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.42 NAME 'sambaAlgorithmicRidBase' DESC 'Base at which the samba RID generation algorithm should operate' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.58 NAME 'sambaMinPwdLength' DESC 'Minimal password length (default: 5)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.59 NAME 'sambaPwdHistoryLength' DESC 'Length of Password History Entries (default: 0 => off)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.60 NAME 'sambaLogonToChgPwd' DESC 'Force Users to logon for password change (default: 0 => off, 2 => on)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.61 NAME 'sambaMaxPwdAge' DESC 'Maximum password age, in seconds (default: -1 => never expire passwords)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.62 NAME 'sambaMinPwdAge' DESC 'Minimum password age, in seconds (default: 0 => allow immediate password change)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.63 NAME 'sambaLockoutDuration' DESC 'Lockout duration in minutes (default: 30, -1 => forever)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.64 NAME 'sambaLockoutObservationWindow' DESC 'Reset time after lockout in minutes (default: 30)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.65 NAME 'sambaLockoutThreshold' DESC 'Lockout users after bad logon attempts (default: 0 => off)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.66 NAME 'sambaForceLogoff' DESC 'Disconnect Users outside logon hours (default: -1 => off, 0 => on)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.4.1.7165.2.1.67 NAME 'sambaRefuseMachinePwdChange' DESC 'Allow Machine Password changes (default: 0 => off)' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )"
      ],
      objectClasses: [
        "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
        "( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )",
        "( 1.3.6.1.1.1.2.2 NAME 'posixGroup' SUP top STRUCTURAL MUST ( cn $ gidNumber ) MAY ( userPassword $ memberUid $ description ) )",
        // Samba 3 schema subset (MAY lists trimmed to attributes defined above, to stay self-contained)
        "( 1.3.6.1.4.1.7165.2.2.6 NAME 'sambaSamAccount' DESC 'Samba 3.0 Auxilary SAM Account' SUP top AUXILIARY MUST ( uid $ sambaSID ) MAY ( cn $ sambaLMPassword $ sambaNTPassword $ sambaPwdLastSet $ sambaAcctFlags $ displayName $ sambaPrimaryGroupSID $ sambaDomainName $ sambaPasswordHistory $ description ) )",
        "( 1.3.6.1.4.1.7165.2.2.4 NAME 'sambaGroupMapping' DESC 'Samba Group Mapping' SUP top AUXILIARY MUST ( gidNumber $ sambaSID $ sambaGroupType ) MAY ( displayName $ description ) )",
        "( 1.3.6.1.4.1.7165.2.2.11 NAME 'sambaIdmapEntry' DESC 'Mapping from a SID to an ID' SUP top AUXILIARY MUST ( sambaSID ) MAY ( uidNumber $ gidNumber ) )",
        "( 1.3.6.1.4.1.7165.2.2.5 NAME 'sambaDomain' DESC 'Samba Domain Information' SUP top STRUCTURAL MUST ( sambaDomainName $ sambaSID ) MAY ( sambaAlgorithmicRidBase $ sambaMinPwdLength $ sambaPwdHistoryLength $ sambaLogonToChgPwd $ sambaMaxPwdAge $ sambaMinPwdAge $ sambaLockoutDuration $ sambaLockoutObservationWindow $ sambaLockoutThreshold $ sambaForceLogoff $ sambaRefuseMachinePwdChange ) )"
      ]
    }
  };
  if (req.filter.matches(obj.attributes, false)) {
    res.send(obj);
  } else {
    logDebug({ name: 'subschema' }, () => `Subschema filter did not match, sending no entry: ${req.filter.toString()}`);
  }
  res.end();
}, endSuccess);

// Search implementation for basic search for Directory Information Tree and the LDAP Root DSE
server.search('', lowerCaseRequestedAttributes, (req, res) => {
  logDebug({ name: 'root DSE' }, "Empty request, return directory information");
  const obj = {
    "attributes": {
      "objectClass": ["top", "OpenLDAProotDSE"],
      "subschemaSubentry": ["cn=subschema"],
      // Advertise the actual configured naming context(s). The Root DSE is queried with an empty
      // base DN, so req.dn has no "o" component; deriving it from the request yields "o=undefined"
      // and clients (Synology DSM) would use that bogus base DN for user/group lookups.
      "namingContexts": config.sites.map((s) => `o=${s.name}`),
      // DSM speaks LDAPv3. Deliberately advertise no supportedControl (e.g. paged results),
      // so the client requests the full result set in one response instead of paging.
      "supportedLDAPVersion": ["3"],
    },
    "dn": "",
  };

  if (req.filter.matches(obj.attributes, false)) {
    res.send(obj);
  }

  res.end();
}, endSuccess);

// Start LDAP server
server.listen(parseInt(config.ldapPort), config.ldapIp, () => {
  const version = JSON.parse(fs.readFileSync(new URL('./package.json', import.meta.url), { encoding: "utf8" }))['version'];
  logInfo({ name: 'root logger' }, `ChurchTools-LDAP-Wrapper ${version} listening @ ${server.url}, ` +
      `cache ${config.cacheDisabled ? "disabled" : `lifetime ${config.cacheLifetime} ms`}`);
});
