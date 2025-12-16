import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { Call } from 'starknet';
import { CavosNativeSDK } from '../CavosNativeSDK';
import { CavosNativeConfig, UserInfo, LoginProvider, OnrampProvider } from '../types';
import * as WebBrowser from 'expo-web-browser';
import * as AuthSession from 'expo-auth-session';

// Simplified context interface matching React SDK
interface CavosNativeContextValue {
    // Core state
    cavos: CavosNativeSDK;
    isAuthenticated: boolean;
    user: UserInfo | null;
    address: string | null;
    isLoading: boolean;
    requiresWalletCreation: boolean;

    // Auth - simplified API
    login: (provider: LoginProvider, redirectUri?: string) => Promise<void>;
    logout: () => Promise<void>;

    // Wallet
    createWallet: () => Promise<void>;

    // Transactions
    execute: (calls: Call | Call[], options?: { gasless?: boolean }) => Promise<string>;

    // Utility
    getOnramp: (provider: OnrampProvider) => string;
}

const CavosNativeContext = createContext<CavosNativeContextValue | null>(null);

interface CavosNativeProviderProps {
    config: CavosNativeConfig;
    children: ReactNode;
}

export function CavosNativeProvider({ config, children }: CavosNativeProviderProps) {
    // Create SDK once
    const [cavos] = useState(() => new CavosNativeSDK(config));

    // State
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState<UserInfo | null>(null);
    const [address, setAddress] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [requiresWalletCreation, setRequiresWalletCreation] = useState(false);

    // Initialize on mount
    useEffect(() => {
        const initialize = async () => {
            try {
                setIsLoading(true);

                // Check for existing passkey wallet first
                const hasLocalWallet = await cavos.hasWalletLocally();
                if (hasLocalWallet) {
                    try {
                        await cavos.loadWallet();
                        setAddress(cavos.getAddress());
                        setIsAuthenticated(true);
                    } catch (e) {
                        console.log('[CavosProvider] Needs passkey auth to load wallet');
                    }
                    setIsLoading(false);
                    return;
                }

                // Try to restore OAuth session
                await cavos.init();

                if (cavos.isAuthenticated()) {
                    setIsAuthenticated(true);
                    setUser(cavos.getUserInfo());

                    const addr = cavos.getAddress();
                    if (addr) {
                        setAddress(addr);
                    } else {
                        // Has OAuth session but no wallet
                        const hasWallet = await cavos.hasWallet();
                        setRequiresWalletCreation(!hasWallet);
                    }
                }
            } catch (error) {
                console.error('[CavosProvider] Init error:', error);
            } finally {
                setIsLoading(false);
            }
        };

        initialize();
    }, [cavos]);

    // Unified login - works like React SDK: login('google') or login('apple')
    const login = useCallback(async (provider: LoginProvider, redirectUri?: string) => {
        setIsLoading(true);
        try {
            // Get login URL from backend
            const finalRedirectUri = redirectUri || AuthSession.makeRedirectUri({ scheme: 'cavos' });
            const loginUrl = await cavos.getLoginUrl(provider, finalRedirectUri);

            // Open browser for OAuth
            const result = await WebBrowser.openAuthSessionAsync(loginUrl, finalRedirectUri);

            if (result.type === 'success' && result.url) {
                // Parse auth_data from callback URL
                const url = new URL(result.url);
                const authData = url.searchParams.get('auth_data');

                if (authData) {
                    // Decode the auth data
                    let decodedData = decodeURIComponent(authData);
                    while (decodedData.startsWith('%7B') || decodedData.startsWith('%257B')) {
                        decodedData = decodeURIComponent(decodedData);
                    }

                    const parsedData = JSON.parse(decodedData);

                    // Set auth data in SDK
                    await cavos.setAuthData({
                        access_token: parsedData.access_token,
                        user: parsedData.user,
                    });

                    // Update state
                    setIsAuthenticated(true);
                    setUser(parsedData.user);

                    // Check if wallet exists
                    const hasWallet = await cavos.hasWallet();
                    if (hasWallet) {
                        setAddress(cavos.getAddress());
                        setRequiresWalletCreation(false);
                    } else {
                        setRequiresWalletCreation(true);
                    }
                }
            }
        } catch (error) {
            console.error('[CavosProvider] Login error:', error);
            throw error;
        } finally {
            setIsLoading(false);
        }
    }, [cavos]);

    // Logout - clears both OAuth and local wallet
    const logout = useCallback(async () => {
        await cavos.logout();
        await cavos.clearWallet();
        setIsAuthenticated(false);
        setUser(null);
        setAddress(null);
        setRequiresWalletCreation(false);
    }, [cavos]);

    // Create wallet - unified for both OAuth and passkey-only
    const createWallet = useCallback(async () => {
        setIsLoading(true);
        try {
            await cavos.createWallet();
            setAddress(cavos.getAddress());
            setRequiresWalletCreation(false);
            // For passkey-only, mark as authenticated after wallet creation
            if (!user) {
                setIsAuthenticated(true);
            }
        } catch (error) {
            console.error('[CavosProvider] Create wallet error:', error);
            throw error;
        } finally {
            setIsLoading(false);
        }
    }, [cavos, user]);

    // Execute transaction
    const execute = useCallback(async (calls: Call | Call[], options?: { gasless?: boolean }) => {
        return cavos.execute(calls, options);
    }, [cavos]);

    // Get onramp URL
    const getOnramp = useCallback((provider: OnrampProvider) => {
        return cavos.getOnramp(provider);
    }, [cavos]);

    const value: CavosNativeContextValue = {
        cavos,
        isAuthenticated,
        user,
        address,
        isLoading,
        requiresWalletCreation,
        login,
        logout,
        createWallet,
        execute,
        getOnramp,
    };

    return (
        <CavosNativeContext.Provider value={value}>
            {children}
        </CavosNativeContext.Provider>
    );
}

/**
 * Hook to access Cavos SDK - same API as React web SDK
 */
export function useCavosNative(): CavosNativeContextValue {
    const context = useContext(CavosNativeContext);
    if (!context) {
        throw new Error('useCavosNative must be used within a CavosNativeProvider');
    }
    return context;
}

// Alias for consistency with web SDK
export const useCavos = useCavosNative;
