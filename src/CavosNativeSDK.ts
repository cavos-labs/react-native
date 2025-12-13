import { Account, Call, CallData, ec, hash, RpcProvider, CairoOption, CairoCustomEnum } from 'starknet';
import { NativeWalletManager } from './wallet/NativeWalletManager';
import { NativePasskeyManager, PasskeyRegistrationResult, CryptoKeyLike } from './security/NativePasskeyManager';
import { CavosNativeConfig, UserInfo, DecryptedWallet, LoginProvider, OnrampProvider, TypedData, Signature } from './types';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';
import * as Crypto from 'expo-crypto';

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
    private static readonly AUTH_TOKEN_KEY = '@cavos/auth_token';
    private static readonly USER_INFO_KEY = '@cavos/user_info';
    private static readonly PASSKEY_WALLET_KEY = '@cavos/passkey_wallet';
    private static readonly BACKEND_URL = 'https://cavos.xyz';

    // Passkey-only wallet state
    private passkeyWallet: DecryptedWallet | null = null;
    private passkeyOnlyMode: boolean = false;
    private passkeyManager: NativePasskeyManager | null = null;
    private provider: RpcProvider | null = null;

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
     * Initialize SDK and restore session if available
     */
    async init(): Promise<void> {
        // Validate MAU limits
        await this.validateAccess();

        // Try to restore auth session
        await this.restoreSession();

        if (this.userInfo && this.accessToken) {
            // Initialize wallet manager
            await this.initializeWalletManager();
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
        const response = await axios.get(`${CavosNativeSDK.BACKEND_URL}/api/auth/${provider}`, {
            params: {
                redirect_uri: redirectUri,
                app_id: this.config.appId,
            },
        });

        return response.data.authorizationUrl;
    }

    /**
     * Initialize wallet manager
     */
    private async initializeWalletManager(): Promise<void> {
        if (!this.userInfo || !this.accessToken) {
            throw new Error('User not authenticated');
        }

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
            await this.walletManager.loadWallet(this.userInfo);
        } catch (error: any) {
            if (error.message !== 'No wallet found') {
                throw error;
            }
            // Wallet doesn't exist yet, will need to create
        }
    }

    /**
     * Create a new wallet
     */
    async createWallet(): Promise<void> {
        if (!this.userInfo) {
            throw new Error('User not authenticated');
        }

        if (this.isLimitExceeded) {
            throw new Error('MAU limit reached. Upgrade your plan to create more wallets.');
        }

        if (!this.walletManager) {
            this.walletManager = new NativeWalletManager(
                this.config.appId,
                this.config.rpId,
                this.config.starknetRpcUrl!,
                this.config.network || 'sepolia',
                CavosNativeSDK.BACKEND_URL
            );
            this.walletManager.setAccessToken(this.accessToken!);
        }

        await this.walletManager.createWallet(this.userInfo);

        // Auto-deploy
        await this.walletManager.deployAccountWithPaymaster(
            this.config.paymasterApiKey!,
            this.config.network || 'sepolia'
        );
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
     * Execute a transaction
     */
    async execute(calls: Call | Call[], options?: { gasless?: boolean }): Promise<string> {
        const account = this.getAccount();
        if (!account) {
            throw new Error('Account not initialized. Please login first.');
        }

        const callsArray = Array.isArray(calls) ? calls : [calls];

        if (options?.gasless !== false) {
            // Use AVNU Paymaster for gasless execution
            const network = this.config.network || 'sepolia';
            const baseUrl = network === 'sepolia'
                ? 'https://sepolia.api.avnu.fi'
                : 'https://starknet.api.avnu.fi';

            // Build typed data
            const typedDataResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.config.paymasterApiKey!,
                },
                body: JSON.stringify({
                    userAddress: account.address,
                    calls: callsArray.map(call => ({
                        contractAddress: call.contractAddress,
                        entrypoint: call.entrypoint,
                        calldata: call.calldata || [],
                    })),
                }),
            });

            if (!typedDataResponse.ok) {
                throw new Error(await typedDataResponse.text());
            }

            const typedData = await typedDataResponse.json();

            // Sign
            const signature = await account.signMessage(typedData.typedData);

            // Execute
            const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.config.paymasterApiKey!,
                },
                body: JSON.stringify({
                    userAddress: account.address,
                    typedData: typedData.typedData,
                    signature: Array.isArray(signature) ? signature : [signature.r, signature.s],
                }),
            });

            if (!executeResponse.ok) {
                throw new Error(await executeResponse.text());
            }

            const result = await executeResponse.json();
            return result.transactionHash;
        } else {
            // Regular execution (user pays gas)
            const result = await account.execute(callsArray);
            return result.transaction_hash;
        }
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

    // Getters
    getAddress(): string | null {
        return this.walletManager?.getAddress() || null;
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
        return this.walletManager?.getAccount() || null;
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
    // PASSKEY-ONLY WALLET METHODS (No OAuth needed)
    // ============================================

    // ArgentX account class hash
    private static readonly ARGENT_ACCOUNT_CLASS_HASH = '0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f';

    /**
     * Create a wallet using ONLY a passkey (FaceID/TouchID)
     * No OAuth login required. Wallet is stored locally.
     */
    async createPasskeyOnlyWallet(): Promise<void> {
        // Initialize passkey manager
        this.passkeyManager = new NativePasskeyManager(this.config.rpId);

        // Initialize provider
        this.provider = new RpcProvider({
            nodeUrl: this.config.starknetRpcUrl!,
        });

        // 1. Register passkey with anonymous ID
        const { encryptionKey, credentialId } = await this.passkeyManager.registerAnonymous();

        // 2. Generate wallet keypair
        const privateKey = ec.starkCurve.utils.randomPrivateKey();
        const publicKey = ec.starkCurve.getStarkKey(privateKey);

        // 3. Compute wallet address
        const address = await this.computePasskeyWalletAddress(publicKey);

        const privateKeyHex = '0x' + Buffer.from(privateKey).toString('hex');
        const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

        // 4. Encrypt private key
        const { ciphertext, iv } = await this.passkeyManager.encrypt(encryptionKey, privateKeyHex);

        // 5. Store locally using SecureStore
        await SecureStore.setItemAsync(
            CavosNativeSDK.PASSKEY_WALLET_KEY,
            JSON.stringify({
                credentialId,
                address,
                publicKey: publicKeyHex,
                encryptedBlob: `${iv}:${ciphertext}`,
            })
        );

        // 6. Set wallet state
        this.passkeyWallet = {
            address,
            publicKey: publicKeyHex,
            privateKey: privateKeyHex,
        };
        this.passkeyOnlyMode = true;

        // 7. Auto-deploy
        await this.deployPasskeyWallet();
    }

    /**
     * Load an existing passkey-only wallet
     * User will be prompted for FaceID/TouchID
     */
    async loadPasskeyOnlyWallet(): Promise<void> {
        // Get stored wallet data
        const dataStr = await SecureStore.getItemAsync(CavosNativeSDK.PASSKEY_WALLET_KEY);
        if (!dataStr) {
            throw new Error('No passkey wallet found');
        }

        const data = JSON.parse(dataStr);

        // Initialize passkey manager
        this.passkeyManager = new NativePasskeyManager(this.config.rpId);

        // Initialize provider
        this.provider = new RpcProvider({
            nodeUrl: this.config.starknetRpcUrl!,
        });

        // Authenticate with passkey (triggers FaceID/TouchID)
        const challenge = Crypto.getRandomBytes(32);
        const { encryptionKey } = await this.passkeyManager.authenticate(challenge);

        // Decrypt private key
        const [iv, ciphertext] = data.encryptedBlob.split(':');
        const privateKeyHex = await this.passkeyManager.decrypt(encryptionKey, ciphertext, iv);

        // Set wallet state
        this.passkeyWallet = {
            address: data.address,
            publicKey: data.publicKey,
            privateKey: privateKeyHex,
        };
        this.passkeyOnlyMode = true;
    }

    /**
     * Check if a passkey-only wallet exists locally
     */
    async hasPasskeyOnlyWallet(): Promise<boolean> {
        try {
            const data = await SecureStore.getItemAsync(CavosNativeSDK.PASSKEY_WALLET_KEY);
            return data !== null;
        } catch {
            return false;
        }
    }

    /**
     * Clear passkey-only wallet from local storage
     */
    async clearPasskeyOnlyWallet(): Promise<void> {
        await SecureStore.deleteItemAsync(CavosNativeSDK.PASSKEY_WALLET_KEY);
        this.passkeyWallet = null;
        this.passkeyOnlyMode = false;
    }

    /**
     * Check if currently using passkey-only mode
     */
    isPasskeyOnlyMode(): boolean {
        return this.passkeyOnlyMode;
    }

    /**
     * Get passkey-only wallet address
     */
    getPasskeyOnlyAddress(): string | null {
        return this.passkeyWallet?.address || null;
    }

    /**
     * Get passkey-only account for transactions
     */
    getPasskeyOnlyAccount(): Account | null {
        if (!this.passkeyWallet || !this.provider) return null;
        return new Account(this.provider, this.passkeyWallet.address, this.passkeyWallet.privateKey);
    }

    /**
     * Compute wallet address for passkey-only wallet
     */
    private async computePasskeyWalletAddress(publicKey: string): Promise<string> {
        const starkKeyPub = publicKey;
        const signer = new CairoCustomEnum({ Starknet: { pubkey: starkKeyPub } });
        const guardian = new CairoOption(1);
        const constructorCallData = CallData.compile({ owner: signer, guardian: guardian });

        return hash.calculateContractAddressFromHash(
            CavosNativeSDK.ARGENT_ACCOUNT_CLASS_HASH,
            CavosNativeSDK.ARGENT_ACCOUNT_CLASS_HASH,
            constructorCallData,
            0
        );
    }

    /**
     * Deploy passkey-only wallet via AVNU Paymaster
     */
    private async deployPasskeyWallet(): Promise<string> {
        if (!this.passkeyWallet) throw new Error('No passkey wallet');

        const account = this.getPasskeyOnlyAccount();
        if (!account) throw new Error('Failed to create account');

        // Build deployment data
        const starkKeyPub = this.passkeyWallet.publicKey;
        const signer = new CairoCustomEnum({ Starknet: { pubkey: starkKeyPub } });
        const guardian = new CairoOption(1);
        const constructorCallData = CallData.compile({ owner: signer, guardian: guardian });

        const deploymentData = {
            class_hash: CavosNativeSDK.ARGENT_ACCOUNT_CLASS_HASH,
            salt: CavosNativeSDK.ARGENT_ACCOUNT_CLASS_HASH,
            unique: '0x0',
            calldata: constructorCallData.map((x) => `0x${BigInt(x).toString(16)}`),
        };

        const network = this.config.network || 'sepolia';
        const baseUrl = network === 'sepolia'
            ? 'https://sepolia.api.avnu.fi'
            : 'https://starknet.api.avnu.fi';

        // Deploy account
        const deployResponse = await fetch(`${baseUrl}/paymaster/v1/deploy-account`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'api-key': this.config.paymasterApiKey!,
            },
            body: JSON.stringify({
                userAddress: this.passkeyWallet.address,
                deploymentData,
            }),
        });

        if (!deployResponse.ok) throw new Error(await deployResponse.text());
        const deployResult = await deployResponse.json();

        if (deployResult.transactionHash && this.provider) {
            await this.provider.waitForTransaction(deployResult.transactionHash);
        }

        return deployResult.transactionHash;
    }
}
