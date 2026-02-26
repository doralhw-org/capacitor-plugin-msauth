import { PublicClientApplication } from '@azure/msal-browser';
import { WebPlugin } from '@capacitor/core';
const TENANT_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9.-]*$/;
export class MsAuth extends WebPlugin {
    async login(options) {
        const context = await this.createContext(options);
        try {
            if (options.interactionType === 'redirect') {
                const redirectResult = await context.handleRedirectPromise();
                if (redirectResult) {
                    return {
                        accessToken: redirectResult.accessToken,
                        idToken: redirectResult.idToken,
                        scopes: redirectResult.scopes,
                    };
                }
            }
            return await this.acquireTokenSilently(context, options.scopes).catch(() => this.acquireTokenInteractively(context, options));
        }
        catch (error) {
            console.error('MSAL: Error occurred while logging in', error);
            throw error;
        }
    }
    async logout(options) {
        const context = await this.createContext(options);
        if (options.interactionType === 'redirect') {
            await context.handleRedirectPromise();
        }
        if (!context.getAllAccounts()[0]) {
            return Promise.reject(new Error('Nothing to sign out from.'));
        }
        if (options.interactionType === 'redirect') {
            return context.logoutRedirect();
        }
        return context.logoutPopup();
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
                cacheLocation: options.interactionType === 'redirect' ? 'localStorage' : 'sessionStorage',
            },
        };
        return await PublicClientApplication.createPublicClientApplication(config);
    }
    getCurrentUrl() {
        return window.location.href.split(/[?#]/)[0];
    }
    async acquireTokenInteractively(context, options) {
        const prompt = options.prompt ?? 'select_account';
        if (options.interactionType === 'redirect') {
            await context.acquireTokenRedirect({
                scopes: options.scopes,
                prompt,
            });
            // acquireTokenRedirect navigates away; this promise never resolves in practice.
            return new Promise(() => { });
        }
        const { accessToken, idToken } = await context.acquireTokenPopup({
            scopes: options.scopes,
            prompt,
        });
        return { accessToken, idToken, scopes: options.scopes };
    }
    async acquireTokenSilently(context, scopes) {
        const { accessToken, idToken } = await context.acquireTokenSilent({
            scopes,
            account: context.getAllAccounts()[0],
        });
        return { accessToken, idToken, scopes };
    }
}
//# sourceMappingURL=web.js.map