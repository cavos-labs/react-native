import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { Account, Call } from 'starknet';
import { CavosNativeSDK } from '../CavosNativeSDK';
import { CavosNativeConfig, UserInfo, LoginProvider, OnrampProvider } from '../types';

interface CavosNativeContextValue {
    // State
    isInitialized: boolean;
    isLoading: boolean;
    isAuthenticated: boolean;
    address: string | null;
    user: UserInfo | null;
    error: Error | null;
    requiresWalletCreation: boolean;

    // Auth methods
    getLoginUrl: (provider: LoginProvider, redirectUri: string) => Promise<string>;
    setAuthData: (authData: { access_token: string; user: UserInfo }) => Promise<void>;
    logout: () => Promise<void>;

    // Wallet methods
    createWallet: () => Promise<void>;
    retryWalletUnlock: () => Promise<void>;

    // Transaction methods
    execute: (calls: Call | Call[], options?: { gasless?: boolean }) => Promise<string>;

    // Utility methods
    getBalance: () => Promise<string>;
    getOnramp: (provider: OnrampProvider) => string;
    isPasskeySupported: () => Promise<boolean>;

    // SDK instance (for advanced usage)
    sdk: CavosNativeSDK | null;
}

const CavosNativeContext = createContext<CavosNativeContextValue | null>(null);

interface CavosNativeProviderProps extends CavosNativeConfig {
    children: ReactNode;
}

export function CavosNativeProvider({
    children,
    ...config
}: CavosNativeProviderProps) {
    const [sdk, setSdk] = useState<CavosNativeSDK | null>(null);
    const [isInitialized, setIsInitialized] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [address, setAddress] = useState<string | null>(null);
    const [user, setUser] = useState<UserInfo | null>(null);
    const [error, setError] = useState<Error | null>(null);
    const [requiresWalletCreation, setRequiresWalletCreation] = useState(false);

    // Initialize SDK
    useEffect(() => {
        const initSDK = async () => {
            try {
                setIsLoading(true);
                setError(null);

                const sdkInstance = new CavosNativeSDK(config);
                await sdkInstance.init();

                setSdk(sdkInstance);
                setIsInitialized(true);
                setIsAuthenticated(sdkInstance.isAuthenticated());
                setAddress(sdkInstance.getAddress());
                setUser(sdkInstance.getUserInfo());

                // Check if wallet creation is needed
                if (sdkInstance.isAuthenticated() && !sdkInstance.getAddress()) {
                    const hasWallet = await sdkInstance.hasWallet();
                    setRequiresWalletCreation(!hasWallet);
                }
            } catch (err) {
                console.error('[CavosNativeProvider] Initialization failed:', err);
                setError(err as Error);
            } finally {
                setIsLoading(false);
            }
        };

        initSDK();
    }, [config.appId, config.rpId, config.network]);

    // Get login URL
    const getLoginUrl = useCallback(async (provider: LoginProvider, redirectUri: string): Promise<string> => {
        if (!sdk) throw new Error('SDK not initialized');
        return sdk.getLoginUrl(provider, redirectUri);
    }, [sdk]);

    // Set auth data after OAuth
    const setAuthData = useCallback(async (authData: { access_token: string; user: UserInfo }): Promise<void> => {
        if (!sdk) throw new Error('SDK not initialized');

        setIsLoading(true);
        try {
            await sdk.setAuthData(authData);
            setIsAuthenticated(true);
            setUser(authData.user);
            setAddress(sdk.getAddress());

            // Check if wallet creation is needed
            if (!sdk.getAddress()) {
                const hasWallet = await sdk.hasWallet();
                setRequiresWalletCreation(!hasWallet);
            }
        } catch (err) {
            setError(err as Error);
            throw err;
        } finally {
            setIsLoading(false);
        }
    }, [sdk]);

    // Logout
    const logout = useCallback(async (): Promise<void> => {
        if (!sdk) return;

        await sdk.logout();
        setIsAuthenticated(false);
        setAddress(null);
        setUser(null);
        setRequiresWalletCreation(false);
    }, [sdk]);

    // Create wallet
    const createWallet = useCallback(async (): Promise<void> => {
        if (!sdk) throw new Error('SDK not initialized');

        setIsLoading(true);
        try {
            await sdk.createWallet();
            setAddress(sdk.getAddress());
            setRequiresWalletCreation(false);
        } catch (err) {
            setError(err as Error);
            throw err;
        } finally {
            setIsLoading(false);
        }
    }, [sdk]);

    // Retry wallet unlock
    const retryWalletUnlock = useCallback(async (): Promise<void> => {
        if (!sdk) throw new Error('SDK not initialized');

        setIsLoading(true);
        try {
            await sdk.retryWalletUnlock();
            setAddress(sdk.getAddress());
            setRequiresWalletCreation(false);
        } catch (err) {
            setError(err as Error);
            throw err;
        } finally {
            setIsLoading(false);
        }
    }, [sdk]);

    // Execute transaction
    const execute = useCallback(async (calls: Call | Call[], options?: { gasless?: boolean }): Promise<string> => {
        if (!sdk) throw new Error('SDK not initialized');
        return sdk.execute(calls, options);
    }, [sdk]);

    // Get balance
    const getBalance = useCallback(async (): Promise<string> => {
        if (!sdk) return '0';
        return sdk.getBalance();
    }, [sdk]);

    // Get onramp URL
    const getOnramp = useCallback((provider: OnrampProvider): string => {
        if (!sdk) throw new Error('SDK not initialized');
        return sdk.getOnramp(provider);
    }, [sdk]);

    // Check passkey support
    const isPasskeySupported = useCallback(async (): Promise<boolean> => {
        if (!sdk) return false;
        return sdk.isPasskeySupported();
    }, [sdk]);

    const value: CavosNativeContextValue = {
        isInitialized,
        isLoading,
        isAuthenticated,
        address,
        user,
        error,
        requiresWalletCreation,
        getLoginUrl,
        setAuthData,
        logout,
        createWallet,
        retryWalletUnlock,
        execute,
        getBalance,
        getOnramp,
        isPasskeySupported,
        sdk,
    };

    return (
        <CavosNativeContext.Provider value={value}>
            {children}
        </CavosNativeContext.Provider>
    );
}

/**
 * Hook to access Cavos Native SDK
 */
export function useCavosNative(): CavosNativeContextValue {
    const context = useContext(CavosNativeContext);
    if (!context) {
        throw new Error('useCavosNative must be used within a CavosNativeProvider');
    }
    return context;
}

// Alias for API consistency with web SDK
export const useCavos = useCavosNative;
