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

        // Cache lifetime of the user/group data in milliseconds. 0 (or "off") disables the cache,
        // so every LDAP search fetches fresh data from ChurchTools - useful when the client caches
        // the LDAP data itself (e.g. Synology DSM).
        this.cacheLifetime = CtldapConfig.asCacheLifetime(config.cacheLifetime);
        this.cacheDisabled = this.cacheLifetime <= 0;
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
        // Custom-field-based group sync: checkbox group fields in ChurchTools decide which
        // groups become LDAP groups and which members they carry (see ctldap.yml).
        this.groupSyncFields = CtldapConfig.asGroupSyncFields(config);
        // Name suffixes of the variant groups. All variants except "members" require a suffix
        // (it keeps the variant DNs distinct); the "members" suffix is optional (default none).
        // Brackets in a suffix are removed from the resulting cn anyway (see ldapSafeName()).
        const suffixes = CtldapConfig.asGroupVariantSuffixes(config);
        this.groupVariantSuffixes = {
            members: suffixes.members,
            leaders: suffixes.leaders || "LeiterInnen",
            leadersSubgroupLeaders: suffixes.leadersSubgroupLeaders
                || "LeiterInnen inkl. untergeordnete Gruppen",
            membersSubgroupLeaders: suffixes.membersSubgroupLeaders
                || "inkl. LeiterInnen untergeordneter Gruppen",
            membersSubgroups: suffixes.membersSubgroups || "inkl. untergeordnete Gruppen"
        };
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
                groupFieldMembers: config.groupFieldMembers,
                groupFieldMembersSubgroupLeaders: config.groupFieldMembersSubgroupLeaders,
                groupFieldMembersSubgroups: config.groupFieldMembersSubgroups,
                groupFieldLeaders: config.groupFieldLeaders,
                groupFieldLeadersSubgroupLeaders: config.groupFieldLeadersSubgroupLeaders,
                groupFieldMembersSuffix: config.groupFieldMembersSuffix,
                groupFieldLeadersSuffix: config.groupFieldLeadersSuffix,
                groupFieldLeadersSubgroupLeadersSuffix: config.groupFieldLeadersSubgroupLeadersSuffix,
                groupFieldMembersSubgroupLeadersSuffix: config.groupFieldMembersSubgroupLeadersSuffix,
                groupFieldMembersSubgroupsSuffix: config.groupFieldMembersSubgroupsSuffix
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
     * Parses the cache lifetime in milliseconds. Unset/empty falls back to 5 minutes, while 0,
     * a negative value or one of the keywords "off"/"none"/"false"/"disabled" disables the cache.
     * Non-numeric values throw, so a typo does not silently restore the default lifetime.
     * @param val The raw config value.
     * @return {number} The cache lifetime in ms, 0 meaning "cache disabled".
     */
    static asCacheLifetime (val) {
        if (val === undefined || val === null || String(val).trim() === '') {
            return 300000;  // 5 minutes
        }
        const str = String(val).trim().toLowerCase();
        if (['off', 'none', 'false', 'disabled'].includes(str)) {
            return 0;
        }
        const ms = Number(str);
        if (!Number.isFinite(ms)) {
            throw Error(`Invalid cacheLifetime "${val}", expected milliseconds (0 disables the cache)!`);
        }
        return Math.max(0, ms);
    }

    /**
     * Parses the custom-field-based group sync options: each entry names the ID of a checkbox
     * group field in ChurchTools that marks groups for one LDAP group variant (see ctldap.yml).
     * The IDs are resolved to the fields' information keys via GET /fields on each sync.
     * Unset/empty/"none" (per entry) disables that variant.
     * @param cfg The raw config object (main config or site config).
     * @return {object} The field IDs by variant, each number or undefined.
     */
    static asGroupSyncFields (cfg) {
        return {
            // LDAP group with the group's direct members
            members: CtldapConfig.asFieldId(cfg.groupFieldMembers),
            // LDAP group with the direct members plus the leaders of all subgroups
            membersSubgroupLeaders: CtldapConfig.asFieldId(cfg.groupFieldMembersSubgroupLeaders),
            // LDAP group with the members of the entire subgroup subtree
            membersSubgroups: CtldapConfig.asFieldId(cfg.groupFieldMembersSubgroups),
            // LDAP group with only the group's leaders
            leaders: CtldapConfig.asFieldId(cfg.groupFieldLeaders),
            // LDAP group with the leaders of the group and of all subgroups
            leadersSubgroupLeaders: CtldapConfig.asFieldId(cfg.groupFieldLeadersSubgroupLeaders)
        };
    }

    /**
     * Parses a single ChurchTools field ID, undefined when unset/empty/"none". Invalid values
     * throw, since a typo in a permission-relevant filter must not silently sync all groups.
     * @param val The raw config value.
     * @return {number|undefined} The parsed field ID.
     */
    static asFieldId (val) {
        const str = CtldapConfig.asOptionalString(val);
        if (str === undefined) {
            return undefined;
        }
        const id = Number(str);
        if (!Number.isInteger(id) || id <= 0) {
            throw Error(`Invalid group field ID "${val}", expected a positive integer!`);
        }
        return id;
    }

    /**
     * Parses the name suffixes of the variant groups (undefined entries fall back to defaults,
     * see the constructor; the "members" suffix defaults to none). A suffix is appended to the
     * ChurchTools group name separated by a space and keeps the DNs of a group's variants distinct.
     * @param cfg The raw config object (main config or site config).
     * @return {object} The suffixes by variant, each string or undefined.
     */
    static asGroupVariantSuffixes (cfg) {
        return {
            members: CtldapConfig.asOptionalString(cfg.groupFieldMembersSuffix),
            leaders: CtldapConfig.asOptionalString(cfg.groupFieldLeadersSuffix),
            leadersSubgroupLeaders: CtldapConfig.asOptionalString(cfg.groupFieldLeadersSubgroupLeadersSuffix),
            membersSubgroupLeaders: CtldapConfig.asOptionalString(cfg.groupFieldMembersSubgroupLeadersSuffix),
            membersSubgroups: CtldapConfig.asOptionalString(cfg.groupFieldMembersSubgroupsSuffix)
        };
    }
}