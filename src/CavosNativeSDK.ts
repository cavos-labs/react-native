import { Account, Call } from 'starknet';
import { TransactionManager } from './transaction/TransactionManager';
import { NativeWalletManager } from './wallet/NativeWalletManager';
import { CavosNativeConfig, UserInfo, LoginProvider, OnrampProvider, TypedData, Signature } from './types';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

export class CavosNativeSDK {
    private config: CavosNativeConfig;
    private walletManager: NativeWalletManager | null = null;
    private isLimitExceeded: boolean = false;

    // Auth state
    private accessToken: string | null = null;
    private userInfo: UserInfo | null = null;

    // Default Cavos shared paymaster API key
    private static readonly DEFAULT_PAYMASTER_KEY = 'c37c52b7-ea5a-4426-8121-329a78354b0b';
    private static readonly DEFAULT_RPC_MAINNET = 'https://starknet-mainnet.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';
    private static readonly DEFAULT_RPC_SEPOLIA = 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';
    private static readonly AUTH_TOKEN_KEY = 'cavos.auth_token';
    private static readonly USER_INFO_KEY = 'cavos.user_info';
    private static readonly BACKEND_URL = 'https://cavos.xyz';

    constructor(config: CavosNativeConfig) {
        if (!config.rpId) {
            throw new Error('rpId is required for React Native SDK. This must match the domain where web passkeys are created.');
        }

        this.config = {
            ...config,
            paymasterApiKey: config.paymasterApiKey || CavosNativeSDK.DEFAULT_PAYMASTER_KEY,
            starknetRpcUrl: config.starknetRpcUrl || (
                config.network === 'mainnet'
                    ? CavosNativeSDK.DEFAULT_RPC_MAINNET
                    : CavosNativeSDK.DEFAULT_RPC_SEPOLIA
            ),
        };
    }

    /**
     * Ensure walletManager is initialized (lazy initialization)
     * This is called automatically by wallet methods, no need for manual init()
     */
    private ensureWalletManager(): NativeWalletManager {
        if (!this.walletManager) {
            this.walletManager = new NativeWalletManager(
                this.config.appId,
                this.config.rpId,
                this.config.starknetRpcUrl!,
                this.config.network || 'sepolia',
                CavosNativeSDK.BACKEND_URL
            );
        }
        return this.walletManager;
    }

    /**
     * Initialize SDK and restore session if available
     * Note: This is optional - SDK auto-initializes on first use
     */
    async init(): Promise<void> {
        // Validate MAU limits
        await this.validateAccess();

        // Ensure wallet manager exists
        this.ensureWalletManager();

        // Try to restore auth session
        await this.restoreSession();

        if (this.userInfo && this.accessToken) {
            // For OAuth users, set the access token and try to load wallet
            this.walletManager!.setAccessToken(this.accessToken);
            try {
                console.log('[CavosNativeSDK] Attempting to load OAuth wallet...');
                await this.walletManager!.loadWallet(this.userInfo);
                console.log('[CavosNativeSDK] OAuth wallet loaded:', this.walletManager!.getAddress());
            } catch (error: any) {
                console.log('[CavosNativeSDK] No OAuth wallet found or load failed:', error.message);
            }
        }
    }

    /**
     * Restore auth session from storage
     */
    private async restoreSession(): Promise<boolean> {
        try {
            const token = await SecureStore.getItemAsync(CavosNativeSDK.AUTH_TOKEN_KEY);
            const userInfoStr = await SecureStore.getItemAsync(CavosNativeSDK.USER_INFO_KEY);

            if (token && userInfoStr) {
                this.accessToken = token;
                this.userInfo = JSON.parse(userInfoStr);
                return true;
            }
            return false;
        } catch (error) {
            console.warn('[CavosNativeSDK] Failed to restore session:', error);
            return false;
        }
    }

    /**
     * Save auth session to storage
     */
    private async saveSession(): Promise<void> {
        try {
            if (this.accessToken) {
                await SecureStore.setItemAsync(CavosNativeSDK.AUTH_TOKEN_KEY, this.accessToken);
            }
            if (this.userInfo) {
                await SecureStore.setItemAsync(CavosNativeSDK.USER_INFO_KEY, JSON.stringify(this.userInfo));
            }
        } catch (error) {
            console.warn('[CavosNativeSDK] Failed to save session:', error);
        }
    }

    /**
     * Clear auth session
     */
    private async clearSession(): Promise<void> {
        try {
            await SecureStore.deleteItemAsync(CavosNativeSDK.AUTH_TOKEN_KEY);
            await SecureStore.deleteItemAsync(CavosNativeSDK.USER_INFO_KEY);
        } catch (error) {
            console.warn('[CavosNativeSDK] Failed to clear session:', error);
        }
    }

    /**
     * Set auth data after OAuth callback
     * Call this after handling OAuth redirect in your app
     */
    async setAuthData(authData: {
        access_token: string;
        user: UserInfo;
    }): Promise<void> {
        this.accessToken = authData.access_token;
        this.userInfo = authData.user;

        await this.saveSession();
        await this.initializeWalletManager();
    }

    /**
     * Get OAuth login URL for the specified provider
     * Open this URL in a browser/WebView for authentication
     */
    async getLoginUrl(provider: LoginProvider, redirectUri: string): Promise<string> {
        const response = await axios.get(`${CavosNativeSDK.BACKEND_URL}/api/auth0/${provider}`, {
            params: {
                redirect_uri: redirectUri,
                app_id: this.config.appId,
            },
        });

        return response.data.url;
    }

    /**
     * Initialize wallet manager
     */
    private async initializeWalletManager(): Promise<void> {
        if (!this.userInfo || !this.accessToken) {
            throw new Error('User not authenticated');
        }

        console.log('[CavosNativeSDK] Initializing wallet manager for user:', this.userInfo.id);

        this.walletManager = new NativeWalletManager(
            this.config.appId,
            this.config.rpId,
            this.config.starknetRpcUrl!,
            this.config.network || 'sepolia',
            CavosNativeSDK.BACKEND_URL
        );

        this.walletManager.setAccessToken(this.accessToken);

        // Try to load existing wallet
        try {
            console.log('[CavosNativeSDK] Attempting to load wallet from backend...');
            await this.walletManager.loadWallet(this.userInfo);
            console.log('[CavosNativeSDK] Wallet loaded successfully:', this.walletManager.getAddress());
        } catch (error: any) {
            console.log('[CavosNativeSDK] loadWallet error:', error.message);
            if (error.message !== 'No wallet found') {
                throw error;
            }
            // Wallet doesn't exist yet, will need to create
            console.log('[CavosNativeSDK] No wallet found for this user, will need to create one');
        }
    }

    /**
     * Create a new wallet
     * - For OAuth-authenticated users: creates wallet linked to their social account
     * - For passkey-only users: creates standalone wallet with passkey
     */
    async createWallet(): Promise<void> {
        const manager = this.ensureWalletManager();

        if (this.isLimitExceeded) {
            throw new Error('MAU limit reached. Upgrade your plan to create more wallets.');
        }

        if (this.userInfo && this.accessToken) {
            // OAuth mode: create wallet linked to social account
            manager.setAccessToken(this.accessToken);
            await manager.createWallet(this.userInfo);
            await manager.deployAccountWithPaymaster(
                this.config.paymasterApiKey!,
                this.config.network || 'sepolia'
            );
        } else {
            // Passkey-only mode: Smart Flow (Recover -> Create)
            try {
                await manager.recoverWalletWithPasskey();
            } catch (error) {
                // If recovery fails (e.g. user cancels or no passkey), create new
                await manager.createPasskeyOnlyWallet(this.config.paymasterApiKey!);
            }
        }
    }

    /**
     * Retry wallet unlock
     */
    async retryWalletUnlock(): Promise<void> {
        if (!this.userInfo) {
            throw new Error('User not authenticated');
        }

        if (this.getAddress()) {
            throw new Error('Wallet is already unlocked');
        }

        if (!this.walletManager) {
            throw new Error('Wallet manager not initialized');
        }

        await this.walletManager.loadWallet(this.userInfo);
    }

    /**
     * Execute a transaction using the active account (unified across passkey-only and OAuth)
     */
    async execute(calls: Call | Call[], options?: { gasless?: boolean }): Promise<string> {
        const account = this.getActiveAccount();
        if (!account) {
            throw new Error('No account available. Please create or load a wallet first.');
        }

        const network = this.config.network || 'sepolia';
        const apiKey = this.config.paymasterApiKey;

        if (!apiKey) {
            throw new Error('Paymaster API Key is required for transactions');
        }

        const txManager = new TransactionManager(
            account,
            apiKey,
            network
        );

        return txManager.execute(calls, options);
    }

    /**
     * Validate app access and MAU limits
     */
    private async validateAccess(): Promise<void> {
        try {
            const network = this.config.network || 'sepolia';

            const response = await axios.get(
                `${CavosNativeSDK.BACKEND_URL}/api/apps/${this.config.appId}/validate`,
                { params: { network } }
            );

            const result = response.data;

            if (!result.allowed) {
                this.isLimitExceeded = true;
                console.warn('[Cavos Native SDK] MAU limit exceeded. New wallet creation is blocked.');
                return;
            }

            if (result.warning) {
                console.warn('[Cavos Native SDK]', result.message);
            }
        } catch (error: any) {
            console.warn('[Cavos Native SDK] Validation check failed:', error.message);
        }
    }

    /**
     * Logout and clear all data
     */
    async logout(): Promise<void> {
        await this.clearSession();

        if (this.walletManager) {
            await this.walletManager.clearWalletStorage();
        }

        this.accessToken = null;
        this.userInfo = null;
        this.walletManager = null;
    }

    // Unified getters that work with any wallet type (passkey-only or OAuth)

    /**
     * Get the active wallet address (unified across passkey-only and OAuth)
     */
    getActiveAddress(): string | null {
        // Try passkey-only first
        const passkeyAddr = this.getPasskeyOnlyAddress();
        if (passkeyAddr) {
            return passkeyAddr;
        }
        // Then try OAuth wallet
        return this.walletManager?.getAddress() || null;
    }

    /**
 * Get the active account (unified across passkey-only and OAuth)
 */
    getActiveAccount(): Account | null {
        console.log('[CavosNativeSDK] getActiveAccount called');
        console.log('[CavosNativeSDK] walletManager exists:', !!this.walletManager);
        console.log('[CavosNativeSDK] walletManager mode:', this.walletManager?.getMode());

        // Try passkey-only first
        const passkeyAccount = this.getPasskeyOnlyAccount();
        console.log('[CavosNativeSDK] passkeyAccount:', !!passkeyAccount);
        if (passkeyAccount) {
            return passkeyAccount;
        }
        // Then try OAuth wallet
        const oauthAccount = this.walletManager?.getAccount() || null;
        console.log('[CavosNativeSDK] oauthAccount:', !!oauthAccount);
        return oauthAccount;
    }

    // Legacy getters (for backwards compatibility)
    getAddress(): string | null {
        return this.getActiveAddress();
    }

    getUserInfo(): UserInfo | null {
        return this.userInfo;
    }

    isAuthenticated(): boolean {
        return !!this.accessToken && !!this.userInfo;
    }

    async hasWallet(): Promise<boolean> {
        if (!this.walletManager || !this.userInfo) return false;
        return this.walletManager.hasWallet(this.userInfo);
    }

    async isAccountDeployed(): Promise<boolean> {
        return this.walletManager?.isDeployed() || false;
    }

    async getBalance(): Promise<string> {
        return this.walletManager?.getBalance() || '0';
    }

    getFundingAddress(): string | null {
        return this.walletManager?.getFundingAddress() || null;
    }

    getAccount(): Account | null {
        return this.getActiveAccount();
    }

    /**
     * Check if passkeys are supported on this device
     */
    async isPasskeySupported(): Promise<boolean> {
        if (!this.walletManager) {
            // Create temporary wallet manager to check support
            const tempManager = new NativeWalletManager(
                this.config.appId,
                this.config.rpId,
                this.config.starknetRpcUrl!,
                this.config.network || 'sepolia'
            );
            return tempManager.isPasskeySupported();
        }
        return this.walletManager.isPasskeySupported();
    }

    /**
     * Get onramp URL
     */
    getOnramp(provider: OnrampProvider): string {
        const address = this.getAddress();
        if (!address) {
            throw new Error('No account connected');
        }

        if (this.config.network === 'sepolia') {
            throw new Error('Onramp not available on Sepolia');
        }

        if (provider === 'RAMP_NETWORK') {
            const formattedAddress = this.formatAddress(address);
            const params = new URLSearchParams({
                defaultFlow: 'ONRAMP',
                enabledFlows: 'ONRAMP',
                enabledCryptoAssets: 'STARKNET_*',
                hostApiKey: 'p8skgorascdvryjzeqoah3xxfbpnx79nopzo6pzw',
                userAddress: formattedAddress,
                outAsset: 'STARKNET_USDC',
                inAsset: 'USD',
                inAssetValue: '10000',
            });
            return `https://app.rampnetwork.com/exchange?${params.toString()}`;
        }

        throw new Error(`Unknown onramp provider: ${provider}`);
    }

    private formatAddress(address: string): string {
        if (!address.startsWith('0x')) {
            throw new Error('Address must start with 0x');
        }
        const hexPart = address.slice(2);
        const paddedHex = hexPart.padStart(64, '0');
        return `0x${paddedHex}`;
    }

    // ============================================
    // WALLET LOADING & MANAGEMENT
    // ============================================

    /**
     * Load an existing wallet 
     * User will be prompted for FaceID/TouchID
     */
    async loadWallet(): Promise<void> {
        const manager = this.ensureWalletManager();
        await manager.loadPasskeyOnlyWallet();
    }

    /**
     * Check if a wallet exists locally
     */
    async hasWalletLocally(): Promise<boolean> {
        const manager = this.ensureWalletManager();
        return manager.hasPasskeyOnlyWallet();
    }

    /**
     * Recover wallet from backend using an existing passkey
     */
    async recoverWallet(): Promise<void> {
        const manager = this.ensureWalletManager();
        await manager.recoverWalletWithPasskey();
    }

    /**
     * Clear wallet from local storage
     */
    async clearWallet(): Promise<void> {
        const manager = this.ensureWalletManager();
        await manager.clearPasskeyOnlyWallet();
    }

    // ============================================
    // LEGACY PASSKEY-ONLY METHODS (Deprecated)
    // ============================================

    /** @deprecated Use createWallet() instead */
    async createPasskeyOnlyWallet(): Promise<void> {
        return this.createWallet();
    }

    /** @deprecated Use loadWallet() instead */
    async loadPasskeyOnlyWallet(): Promise<void> {
        return this.loadWallet();
    }

    /** @deprecated Use recoverWallet() instead */
    async recoverWalletWithPasskey(): Promise<void> {
        return this.recoverWallet();
    }

    /** @deprecated Use hasWalletLocally() instead */
    async hasPasskeyOnlyWallet(): Promise<boolean> {
        return this.hasWalletLocally();
    }

    /** @deprecated Use clearWallet() instead */
    async clearPasskeyOnlyWallet(): Promise<void> {
        return this.clearWallet();
    }

    /**
     * Check if currently using passkey-only mode
     */
    isPasskeyOnlyMode(): boolean {
        return this.walletManager?.isPasskeyOnlyMode() || false;
    }

    /** @deprecated Use getAddress() instead */
    getPasskeyOnlyAddress(): string | null {
        // Use walletManager directly to avoid recursion with getActiveAddress
        if (this.walletManager?.isPasskeyOnlyMode()) {
            return this.walletManager.getAddress();
        }
        return null;
    }

    /** @deprecated Use getAccount() instead */
    getPasskeyOnlyAccount(): Account | null {
        // Use walletManager directly to avoid recursion with getActiveAccount
        if (this.walletManager?.isPasskeyOnlyMode()) {
            return this.walletManager.getAccount();
        }
        return null;
    }
}
