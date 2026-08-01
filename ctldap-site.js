/**
 * ctldap - ChurchTools LDAP-Wrapper 3.0
 * @copyright 2017-2023 Michael Lux
 * @licence GNU/GPL v3.0
 */
import ldapEscape from "ldap-escape";
import got from "got";
import bcrypt from "@node-rs/bcrypt";
import argon2 from "@node-rs/argon2";
import { CtldapConfig } from "./ctldap-config.js"
import { CookieJar } from "tough-cookie";
import { logTrace, logWarn } from "./ctldap.js"

export class CtldapSite {

    /**
     * CtldapSite Constructor.
     * @param {CtldapConfig} config The main CtldapConfig for fallback values.
     * @param {string} name The name (i.e. also base DN) of the site.
     * @param {object} site The site's config object.
     */
    constructor(config, name, site) {
        // Take ldapUser from main config if not specified for site.
        this.ldapUser = site.ldapUser || config.ldapUser;
        this.ldapPassword = site.ldapPassword;
        // Default to no mappings: the site created from the main config passes the raw yaml value,
        // which is undefined when the (optional) specialGroupMappings section is missing.
        this.specialGroupMappings = site.specialGroupMappings || {};
        this.dnLowerCase = CtldapConfig.asOptionalBool(site.dnLowerCase);
        this.emailLowerCase = CtldapConfig.asOptionalBool(site.emailLowerCase);
        this.emailsUnique = CtldapConfig.asOptionalBool(site.emailsUnique);
        // Email login, optional per site with fallback to the main config.
        const emailLogin = CtldapConfig.asOptionalBool(site.emailLogin);
        this.emailLogin = emailLogin === undefined ? config.emailLogin : emailLogin;
        // SMB/samba support, optional per site with fallback to the main config.
        const smbEnabled = CtldapConfig.asOptionalBool(site.smbEnabled);
        this.smbEnabled = smbEnabled === undefined ? config.smbEnabled : smbEnabled;
        // Custom-field-based group sync, each field key optional per site with fallback
        // to the main config ("none" explicitly disables a variant for the site).
        const siteFields = CtldapConfig.asGroupSyncFields(site);
        const fieldOrMain = (rawSiteValue, siteValue, mainValue) =>
            rawSiteValue === undefined ? mainValue : siteValue;
        this.groupSyncFields = {
            members: fieldOrMain(site.groupFieldMembers,
                siteFields.members, config.groupSyncFields.members),
            membersSubgroupLeaders: fieldOrMain(site.groupFieldMembersSubgroupLeaders,
                siteFields.membersSubgroupLeaders, config.groupSyncFields.membersSubgroupLeaders),
            membersSubgroups: fieldOrMain(site.groupFieldMembersSubgroups,
                siteFields.membersSubgroups, config.groupSyncFields.membersSubgroups),
            leaders: fieldOrMain(site.groupFieldLeaders,
                siteFields.leaders, config.groupSyncFields.leaders),
            leadersSubgroupLeaders: fieldOrMain(site.groupFieldLeadersSubgroupLeaders,
                siteFields.leadersSubgroupLeaders, config.groupSyncFields.leadersSubgroupLeaders)
        };
        // With at least one field key configured, only groups with a checked field become LDAP groups.
        this.groupSyncActive = Object.values(this.groupSyncFields).some((key) => key !== undefined);
        // Any recursive variant configured -> the group hierarchy must be fetched.
        this.groupSyncNeedsHierarchy = [
            this.groupSyncFields.membersSubgroupLeaders,
            this.groupSyncFields.membersSubgroups,
            this.groupSyncFields.leadersSubgroupLeaders
        ].some((key) => key !== undefined);
        // Any leader-based variant configured -> leader roles from the master data are required.
        this.groupSyncUsesLeaders = [
            this.groupSyncFields.leaders,
            this.groupSyncFields.leadersSubgroupLeaders,
            this.groupSyncFields.membersSubgroupLeaders
        ].some((key) => key !== undefined);
        // Name suffixes of the variant groups, optional per site with fallback to the main
        // config. All variants except "members" require a suffix (unset/empty/"none" falls
        // back to the default), since it is what keeps the variant DNs distinct; the
        // "members" suffix is optional ("none" explicitly disables it for the site).
        const siteSuffixes = CtldapConfig.asGroupVariantSuffixes(site);
        this.groupVariantSuffixes = {
            members: fieldOrMain(site.groupFieldMembersSuffix,
                siteSuffixes.members, config.groupVariantSuffixes.members),
            leaders: siteSuffixes.leaders
                || config.groupVariantSuffixes.leaders,
            leadersSubgroupLeaders: siteSuffixes.leadersSubgroupLeaders
                || config.groupVariantSuffixes.leadersSubgroupLeaders,
            membersSubgroupLeaders: siteSuffixes.membersSubgroupLeaders
                || config.groupVariantSuffixes.membersSubgroupLeaders,
            membersSubgroups: siteSuffixes.membersSubgroups
                || config.groupVariantSuffixes.membersSubgroups
        };
        // Samba matches the sambaDomain entry against its (uppercase) workgroup name.
        this.smbDomainName = (site.smbDomainName || config.smbDomainName).toUpperCase();
        this.smbSidBase = CtldapConfig.asOptionalString(site.smbSidBase) || config.smbSidBase;
        this.name = name;
        this.fnUserDn = (cn) => ldapEscape.dn`cn=${cn},ou=users,o=${name}`;
        this.fnGroupDn = (cn) => ldapEscape.dn`cn=${cn},ou=groups,o=${name}`;
        this.fnSmbDomainDn = (domain) => ldapEscape.dn`sambaDomainName=${domain},o=${name}`;
        // Let us keep cookies, which may improve CT API performance.
        // We have to use a pool of CookieJars in order to avoid ChurchTools HTTP 403 bugs.
        const cookieJars = []
        this.api = got.extend({
            headers: {"Authorization": `Login ${site.apiToken}`},
            prefixUrl: `${site.ctUri.replace(/\/$/g, '')}/api`,
            retry: {
                statusCodes: [403, 408, 413, 429, 500, 502, 503, 504, 521, 522, 524]
            },
            hooks: {
                beforeRequest: [
                    options => {
                        let cookieJar = cookieJars.pop()
                        if (!cookieJar) {
                            // "undefined" is fine as "store" parameter here, it results in memory storage.
                            cookieJar = new CookieJar(undefined);
                            logTrace(site, "Assign new CookieJar.")
                        } else {
                            logTrace(site, () => `Reusing CookieJar: ${JSON.stringify(cookieJar)}`)
                        }
                        options.cookieJar = cookieJar
                    }
                ],
                beforeRetry: [
                    (error, retryCount) => {
                        if (error.response.statusCode === 403) {
                            logWarn(
                                this,
                                `CT API responded with HTTP 403, clearing cookies before retry ${retryCount}...`
                            );
                            error.options.cookieJar.removeAllCookiesSync();
                        }
                    }
                ],
                afterResponse: [
                    (response, _retryWithMergedOptions) => {
                        // Return CookieJar to pool
                        if (response.statusCode === 200) {
                            const cookieJar = response.request.options.cookieJar
                            logTrace(site, () => `Return CookieJar: ${JSON.stringify(cookieJar)}`)
                            cookieJars.push(cookieJar)
                        }
                        return response;
                    }
                ],
            },
            responseType: 'json',
            resolveBodyOnly: true,
            http2: true
        });
        this.adminDn = this.fnUserDn(site.ldapUser);
        this.CACHE = {
            pagination: {}
        };
        this.loginErrorCount = 0;
        this.loginBlockedDate = null;

        const identityFn = (p) => p;
        const stringLowerFn = (s) => typeof s === "string" ? s.toLowerCase() : s;

        if (this.dnLowerCase || ((this.dnLowerCase === undefined) && config.dnLowerCase)) {
            this.compatTransform = stringLowerFn;
        } else {
            this.compatTransform = identityFn;
        }

        if (this.emailLowerCase || ((this.emailLowerCase === undefined) && config.emailLowerCase)) {
            this.compatTransformEmail = stringLowerFn;
        } else {
            this.compatTransformEmail = identityFn;
        }

        if (this.emailsUnique || ((this.emailsUnique === undefined) && config.emailsUnique)) {
            this.uniqueEmails = (users) => {
                const mails = {};
                return users.filter((user) => {
                    if (!user.attributes.email) {
                        return false;
                    }
                    const result = !(user.attributes.email in mails);
                    mails[user.attributes.email] = true;
                    return result;
                });
            };
        } else {
            this.uniqueEmails = identityFn;
        }

        // If LDAP admin password has been provided, set the right verification algorithm based on hash format.
        if (this.ldapPassword) {
            if (/^\$2[yab]\$/.test(this.ldapPassword)) {
                // Assume bcrypt hash
                this.checkPassword = async (password) => {
                    const hash = this.ldapPassword.replace(/^\$2y\$/, '$2a$');
                    if (!await bcrypt.compare(password, hash)) {
                        throw Error("Wrong password, bcrypt hash didn't match!");
                    }
                };
            } else if (/^\$argon2[id]{1,2}\$/.test(this.ldapPassword)) {
                // Assume argon2 hash
                this.checkPassword = async (password) => {
                    if (!await argon2.verify(this.ldapPassword, password)) {
                        throw Error("Wrong password, argon2 hash didn't match!");
                    }
                }
            } else {
                // Assume plaintext password
                this.checkPassword = async (password) => {
                    if (password !== this.ldapPassword) {
                        throw Error("Wrong password, plaintext didn't match!")
                    }
                };
            }
        }
    }

    /**
     * Tries to perform a local LDAP admin authentication, locking for one day after 5 failed login approaches.
     * @param password Password to use for LDAP admin authentication.
     * @returns {Promise<void>} Promise resolves upon successful authentication, rejects on error.
     */
    async authenticateAdmin (password) {
        if (this.loginBlockedDate) {
            const now = new Date();
            const checkDate = new Date(this.loginBlockedDate.getTime() + 1000 * 3600 * 24); // one day
            if (now < checkDate) {
                throw Error("Login blocked!");
            } else {
                this.loginBlockedDate = null;
                this.loginErrorCount = 0;
            }
        }
        try {
            // Delegate password check to the associated algorithm based on type of password hashing, see below.
            await this.checkPassword(password);
        } catch (error) {
            this.loginErrorCount += 1;
            if (this.loginErrorCount > 5) {
                this.loginBlockedDate = new Date();
            }
            throw error;
        }
    };

}