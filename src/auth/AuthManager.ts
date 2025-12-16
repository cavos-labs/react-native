import axios from 'axios';
import { AuthData, UserInfo, OAuthProvider, AuthConfig } from '../types';
import * as SecureStore from 'expo-secure-store';

const STORAGE_KEY = 'cavos.auth_session';

export class AuthManager {
    private backendUrl: string;
    private appId: string;
    private authData: AuthData | null = null;
    private provider: OAuthProvider | null = null;

    constructor(config: AuthConfig) {
        this.backendUrl = config.backendUrl;
        this.appId = config.appId;
    }

    /**
     * Get Google OAuth URL for native app
     * Open this URL in a browser/WebView
     */
    async getGoogleLoginUrl(redirectUri: string): Promise<string> {
        try {
            const response = await axios.get(`${this.backendUrl}/api/auth0/google`, {
                params: {
                    redirect_uri: redirectUri,
                },
            });

            return response.data.url;
        } catch (error: any) {
            console.error('[AuthManager] Google login URL failed:', error);
            throw new Error(`Google login failed: ${error.message}`);
        }
    }

    /**
     * Get Apple OAuth URL for native app
     * Open this URL in a browser/WebView
     */
    async getAppleLoginUrl(redirectUri: string): Promise<string> {
        try {
            const response = await axios.get(`${this.backendUrl}/api/auth0/apple`, {
                params: {
                    redirect_uri: redirectUri,
                },
            });

            return response.data.url;
        } catch (error: any) {
            console.error('[AuthManager] Apple login URL failed:', error);
            throw new Error(`Apple login failed: ${error.message}`);
        }
    }

    /**
     * Handle OAuth callback
     */
    async handleCallback(authDataString: string): Promise<void> {
        try {
            const authData = JSON.parse(decodeURIComponent(authDataString)) as AuthData;

            this.authData = authData;

            // Determine provider from user info
            if (authData.user.email.includes('appleid')) {
                this.provider = { name: 'apple', displayName: 'Apple' };
            } else {
                this.provider = { name: 'google', displayName: 'Google' };
            }

            // Save session
            await this.saveSession();
        } catch (error: any) {
            console.error('[AuthManager] Callback handling failed:', error);
            throw new Error(`Callback handling failed: ${error.message}`);
        }
    }

    /**
     * Set auth data directly (useful for handling deep links)
     */
    async setAuthData(authData: AuthData, provider: OAuthProvider): Promise<void> {
        this.authData = authData;
        this.provider = provider;
        await this.saveSession();
    }

    /**
     * Save session to SecureStore
     */
    private async saveSession(): Promise<void> {
        if (!this.authData || !this.provider) return;

        try {
            const sessionData = {
                authData: this.authData,
                provider: this.provider,
                timestamp: Date.now(),
            };

            await SecureStore.setItemAsync(STORAGE_KEY, JSON.stringify(sessionData));
        } catch (error) {
            console.warn('[AuthManager] Failed to save session:', error);
        }
    }

    /**
     * Restore session from SecureStore
     */
    async restoreSession(): Promise<boolean> {
        try {
            const sessionString = await SecureStore.getItemAsync(STORAGE_KEY);
            if (!sessionString) return false;

            const sessionData = JSON.parse(sessionString);

            this.authData = sessionData.authData;
            this.provider = sessionData.provider;

            return true;
        } catch (error) {
            console.error('[AuthManager] Failed to restore session:', error);
            await this.clearSession();
            return false;
        }
    }

    /**
     * Get current user info
     */
    getUserInfo(): UserInfo | null {
        return this.authData?.user || null;
    }

    /**
     * Get access token
     */
    getAccessToken(): string | null {
        return this.authData?.access_token || null;
    }

    /**
     * Get refresh token
     */
    getRefreshToken(): string | null {
        return this.authData?.refresh_token || null;
    }

    /**
     * Get current provider
     */
    getProvider(): OAuthProvider | null {
        return this.provider;
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated(): boolean {
        return this.authData !== null;
    }

    /**
     * Logout
     */
    async logout(): Promise<void> {
        this.authData = null;
        this.provider = null;
        await this.clearSession();
    }

    /**
     * Clear session from SecureStore
     */
    private async clearSession(): Promise<void> {
        try {
            await SecureStore.deleteItemAsync(STORAGE_KEY);
        } catch (error) {
            console.warn('[AuthManager] Failed to clear session:', error);
        }
    }

    /**
     * Get full auth data
     */
    getAuthData(): AuthData | null {
        return this.authData;
    }

    /**
     * Delete account
     */
    async deleteAccount(appId: string, network: string): Promise<void> {
        const token = this.getAccessToken();
        if (!token) {
            throw new Error('User not authenticated');
        }

        try {
            await axios.delete(`${this.backendUrl}/api/user/delete`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
                data: {
                    app_id: appId,
                    network: network,
                },
            });
        } catch (error: any) {
            console.error('[AuthManager] Failed to delete account:', error);
            throw new Error(`Failed to delete account: ${error.message}`);
        }
    }

    /**
     * Get app ID
     */
    getAppId(): string {
        return this.appId;
    }
}
