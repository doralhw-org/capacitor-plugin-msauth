var capacitorMsAuth = (function (exports, core, msalBrowser) {
    'use strict';

    const TENANT_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9.-]*$/;
    class MsAuth extends core.WebPlugin {
        async login(options) {
            const context = await this.createContext(options);
            try {
                return await this.acquireTokenSilently(context, options.scopes).catch(() => this.acquireTokenInteractively(context, options.scopes));
            }
            catch (error) {
                console.error('MSAL: Error occurred while logging in', error);
                throw error;
            }
        }
        async logout(options) {
            const context = await this.createContext(options);
            if (!context.getAllAccounts()[0]) {
                return Promise.reject(new Error('Nothing to sign out from.'));
            }
            else {
                return context.logoutPopup();
            }
        }
        logoutAll(options) {
            return this.logout(options);
        }
        async createContext(options) {
            if (options.authorityUrl && !options.authorityUrl.startsWith('https://')) {
                throw new Error('authorityUrl must use HTTPS.');
            }
            if (!options.authorityUrl && options.tenant) {
                if (!TENANT_PATTERN.test(options.tenant)) {
                    throw new Error('Invalid tenant specified.');
                }
            }
            const config = {
                auth: {
                    clientId: options.clientId,
                    authority: options.authorityUrl ?? `https://login.microsoftonline.com/${options.tenant ?? 'common'}`,
                    knownAuthorities: options.knownAuthorities,
                    redirectUri: options.redirectUri ?? this.getCurrentUrl(),
                },
                cache: {
                    cacheLocation: 'sessionStorage',
                },
            };
            return await msalBrowser.PublicClientApplication.createPublicClientApplication(config);
        }
        getCurrentUrl() {
            return window.location.href.split(/[?#]/)[0];
        }
        async acquireTokenInteractively(context, scopes) {
            const { accessToken, idToken } = await context.acquireTokenPopup({
                scopes,
                prompt: 'select_account',
            });
            return { accessToken, idToken, scopes };
        }
        async acquireTokenSilently(context, scopes) {
            const { accessToken, idToken } = await context.acquireTokenSilent({
                scopes,
                account: context.getAllAccounts()[0],
            });
            return { accessToken, idToken, scopes };
        }
    }

    const MsAuthPlugin = core.registerPlugin('MsAuthPlugin', {
        web: () => new MsAuth(),
    });

    exports.MsAuthPlugin = MsAuthPlugin;

    return exports;

})({}, capacitorExports, msalBrowser);
//# sourceMappingURL=plugin.js.map
