/**
 * ctldap - ChurchTools LDAP-Wrapper 3.0
 * @copyright 2017-2023 Michael Lux
 * @licence GNU/GPL v3.0
 */
import { readYamlEnvSync } from "yaml-env-defaults";
import { CtldapSite } from "./ctldap-site.js";

export class CtldapConfig {

    /**
     * CtldapConfig constructor.
     */
    constructor() {
        const yaml = readYamlEnvSync('./ctldap.yml');
        const config = yaml.config;
        this.trace = CtldapConfig.asOptionalBool(config.trace);
        this.debug = this.trace || CtldapConfig.asOptionalBool(config.debug);
        this.ldapIp = config.ldapIp;
        this.ldapPort = config.ldapPort;

        if (typeof config.cacheLifetime !== 'number' && isNaN(config.cacheLifetime)) {
            this.cacheLifetime = 300000;  // 5 minutes
        } else {
            this.cacheLifetime = Number(config.cacheLifetime);
        }
        this.ldapUser = config.ldapUser;
        this.ldapPassword = config.ldapPassword;
        this.ctUri = config.ctUri;
        this.apiToken = config.apiToken;
        this.specialGroupMappings = config.specialGroupMappings || {};
        this.dnLowerCase = CtldapConfig.asOptionalBool(config.dnLowerCase);
        this.emailLowerCase = CtldapConfig.asOptionalBool(config.emailLowerCase);
        this.emailsUnique = CtldapConfig.asOptionalBool(config.emailsUnique);
        this.ldapCertFilename = config.ldapCertFilename;
        this.ldapKeyFilename = config.ldapKeyFilename;
        this.ldapBaseDn = config.ldapBaseDn;
        // Serve email addresses as additional uid values, so logins by email work (e.g. SMB)
        this.emailLogin = CtldapConfig.asOptionalBool(config.emailLogin) || false;
        // Tag-based group sync filter: only groups carrying one of these tags become LDAP groups.
        this.groupSyncTagIds = CtldapConfig.asTagIdList(config.groupSyncTagIds);
        // Groups carrying one of these tags become ADDITIONAL leaders-only LDAP groups
        // (only members with a leader role), named with the leadersOnlyNameSuffix.
        this.groupSyncTagIdsLeadersOnly = CtldapConfig.asTagIdList(config.groupSyncTagIdsLeadersOnly);
        // Brackets in the suffix are removed from the resulting cn anyway (see ldapSafeName()).
        this.leadersOnlyNameSuffix = CtldapConfig.asOptionalString(config.leadersOnlyNameSuffix) || "LeiterIn";
        // Groups carrying this tag include the members of all their subgroups as LDAP members.
        this.recursiveMembersTagId = CtldapConfig.asTagId(config.recursiveMembersTagId);
        // SMB/samba support (NT hash capture on bind + samba attributes)
        this.smbEnabled = CtldapConfig.asOptionalBool(config.smbEnabled) || false;
        this.smbDomainName = config.smbDomainName || "WORKGROUP";
        this.smbSidBase = CtldapConfig.asOptionalString(config.smbSidBase);
        this.smbStoreFile = config.smbStoreFile || "./data/smb-store.json";
        // Configure sites
        const sites = yaml.sites || {};
        // If ldapBaseDn is set, create a site from the global config properties.
        if (config.ldapBaseDn) {
            sites[config.ldapBaseDn] = {
                ldapUser: config.ldapUser,
                ldapPassword: config.ldapPassword,
                ctUri: config.ctUri,
                apiToken: config.apiToken,
                specialGroupMappings: config.specialGroupMappings,
                groupSyncTagIds: config.groupSyncTagIds,
                groupSyncTagIdsLeadersOnly: config.groupSyncTagIdsLeadersOnly,
                leadersOnlyNameSuffix: config.leadersOnlyNameSuffix,
                recursiveMembersTagId: config.recursiveMembersTagId
            }
        }
        this.sites = Object.keys(sites).map((siteName) => new CtldapSite(this, siteName, sites[siteName]));
    }

    static asOptionalBool (val) {
        if (val === undefined) {
            return undefined;
        }
        return (val || 'false').toLowerCase() !== 'false';
    }

    /**
     * Parses an optional string value: undefined/null, the empty string and the keyword "none"
     * map to undefined. "none" is the yml default for optional env vars, because a ${VAR:}
     * placeholder with an empty default is never substituted by yaml-env-defaults - not even
     * when the variable is set.
     * @param val The raw config value.
     * @return {string|undefined} The parsed value.
     */
    static asOptionalString (val) {
        if (val === undefined || val === null) {
            return undefined;
        }
        const str = String(val).trim();
        return (str === '' || str.toLowerCase() === 'none') ? undefined : str;
    }

    /**
     * Parses a ChurchTools tag ID list: a comma-separated string (typical env var input),
     * a YAML list, or a single number. Returns [] when unset/empty/"none". Invalid entries
     * throw, since a typo in a permission-relevant filter must not silently sync all groups.
     * @param val The raw config value.
     * @return {number[]} The parsed tag IDs.
     */
    static asTagIdList (val) {
        const str = Array.isArray(val) ? val.join(',') : CtldapConfig.asOptionalString(val);
        if (str === undefined) {
            return [];
        }
        return str.split(',')
            .map((entry) => entry.trim())
            .filter((entry) => entry !== '')
            .map((entry) => {
                const id = Number(entry);
                if (!Number.isInteger(id) || id <= 0) {
                    throw Error(`Invalid tag ID "${entry}", expected a positive integer!`);
                }
                return id;
            });
    }

    /**
     * Parses a single ChurchTools tag ID, undefined when unset/empty.
     * @param val The raw config value.
     * @return {number|undefined} The parsed tag ID.
     */
    static asTagId (val) {
        const ids = CtldapConfig.asTagIdList(val);
        if (ids.length > 1) {
            throw Error(`Expected a single tag ID, got "${val}"!`);
        }
        return ids.length > 0 ? ids[0] : undefined;
    }
}