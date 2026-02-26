import { PublicClientApplication, type Configuration, type IPublicClientApplication } from '@azure/msal-browser';
import { WebPlugin } from '@capacitor/core';

import type { BaseOptions, MsAuthPlugin } from './definitions';

interface WebBaseOptions extends BaseOptions {
  redirectUri?: string;
}

interface WebLoginOptions extends WebBaseOptions {
  scopes: string[];
  prompt?: 'login' | 'none' | 'consent' | 'create' | 'select_account';
}

type WebLogoutOptions = WebBaseOptions;

interface AuthResult {
  accessToken: string;
  idToken: string;
  scopes: string[];
}

const TENANT_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9.-]*$/;

export class MsAuth extends WebPlugin implements MsAuthPlugin {
  async login(options: WebLoginOptions): Promise<AuthResult> {
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

      return await this.acquireTokenSilently(context, options.scopes).catch(() =>
        this.acquireTokenInteractively(context, options),
      );
    } catch (error) {
      console.error('MSAL: Error occurred while logging in', error);

      throw error;
    }
  }

  async logout(options: WebLogoutOptions): Promise<void> {
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

  logoutAll(options: WebLogoutOptions): Promise<void> {
    return this.logout(options);
  }

  private async createContext(options: WebBaseOptions): Promise<IPublicClientApplication> {
    if (options.authorityUrl && !options.authorityUrl.startsWith('https://')) {
      throw new Error('authorityUrl must use HTTPS.');
    }

    if (!options.authorityUrl && options.tenant) {
      if (!TENANT_PATTERN.test(options.tenant)) {
        throw new Error('Invalid tenant specified.');
      }
    }

    const config: Configuration = {
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

  private getCurrentUrl(): string {
    return window.location.href.split(/[?#]/)[0];
  }

  private async acquireTokenInteractively(context: IPublicClientApplication, options: WebLoginOptions): Promise<AuthResult> {
    const prompt = options.prompt ?? 'select_account';

    if (options.interactionType === 'redirect') {
      await context.acquireTokenRedirect({
        scopes: options.scopes,
        prompt,
      });
      // acquireTokenRedirect navigates away; this promise never resolves in practice.
      return new Promise(() => {});
    }

    const { accessToken, idToken } = await context.acquireTokenPopup({
      scopes: options.scopes,
      prompt,
    });

    return { accessToken, idToken, scopes: options.scopes };
  }

  private async acquireTokenSilently(context: IPublicClientApplication, scopes: string[]): Promise<AuthResult> {
    const { accessToken, idToken } = await context.acquireTokenSilent({
      scopes,
      account: context.getAllAccounts()[0],
    });

    return { accessToken, idToken, scopes };
  }
}
