import { Account, CallData, ec, hash, RpcProvider, CairoOption, CairoCustomEnum } from 'starknet';
import { UserInfo, DecryptedWallet } from '../types';
import { NativePasskeyManager, CryptoKeyLike } from '../security/NativePasskeyManager';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';
import * as Crypto from 'expo-crypto';

export class NativeWalletManager {
    private provider: RpcProvider;
    private account: Account | null = null;
    private passkeyManager: NativePasskeyManager;
    private appId: string;
    private network: string;
    private backendUrl: string;
    private accessToken: string | null = null;

    private currentWallet: DecryptedWallet | null = null;
    private currentAccount: Account | null = null;
    private userEmail: string | null = null;

    // Wallet mode: 'oauth' for Google/Apple login, 'passkey-only' for passkey-only wallets
    private walletMode: 'oauth' | 'passkey-only' | null = null;

    // ArgentX account class hash - using pow's proven working class hash for passkey-only
    private static readonly ARGENT_ACCOUNT_CLASS_HASH_OAUTH = '0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f';
    private static readonly ARGENT_ACCOUNT_CLASS_HASH_PASSKEY = '0x01a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003';

    // Storage keys
    private static readonly WALLET_STORAGE_KEY = 'cavos.wallet_session';
    private static readonly PASSKEY_WALLET_KEY = 'cavos.passkey_wallet';

    constructor(
        appId: string,
        rpId: string,
        starknetRpcUrl: string,
        network: string,
        backendUrl: string = 'https://cavos.xyz'
    ) {
        this.appId = appId;
        this.network = network;
        this.backendUrl = backendUrl;
        this.passkeyManager = new NativePasskeyManager(rpId);

        this.provider = new RpcProvider({
            nodeUrl: starknetRpcUrl,
        });
    }

    /**
     * Set access token for API calls
     */
    setAccessToken(token: string): void {
        this.accessToken = token;
    }

    /**
     * Generate a random hex string of specified length
     */
    private randomHex(length: number): string {
        const randomBytes = Crypto.getRandomBytes(Math.ceil(length / 2));
        let hex = '';
        for (let i = 0; i < randomBytes.length; i++) {
            hex += randomBytes[i].toString(16).padStart(2, '0');
        }
        return hex.slice(0, length);
    }

    /**
     * Create a new wallet with native Passkey encryption
     */
    async createWallet(user: UserInfo): Promise<Account> {
        this.userEmail = user.email;

        // 1. Generate new keypair using 248-bit hex (valid for Stark curve)
        const privateKeyHex = `0x00${this.randomHex(62)}`;
        const publicKey = ec.starkCurve.getStarkKey(privateKeyHex);

        // 2. Compute wallet address
        const address = await this.computeWalletAddress(publicKey);

        const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

        // 3. Register Passkey and derive encryption key
        const challenge = Crypto.getRandomBytes(32);
        const result = await this.passkeyManager.register(user.email, challenge);

        // 4. Encrypt private key
        const { ciphertext, iv } = await this.passkeyManager.encrypt(result.encryptionKey, privateKeyHex);
        const encryptedBlob = `${iv}:${ciphertext}`;

        // 5. Save to Backend API
        await this.saveWalletToApi(user, address, encryptedBlob);

        // 6. Create account instance
        this.currentWallet = {
            address,
            publicKey: publicKeyHex,
            privateKey: privateKeyHex,
        };

        // Save to local storage
        await this.saveWalletToStorage(this.currentWallet);

        this.currentAccount = new Account(this.provider, address, privateKeyHex);
        this.walletMode = 'oauth';

        // Track MAU
        await this.trackUsage(address);

        return this.currentAccount;
    }

    /**
     * Load existing wallet using native Passkey decryption
     */
    async loadWallet(user: UserInfo): Promise<Account> {
        this.userEmail = user.email;

        // Check local storage first
        const cachedWallet = await this.loadWalletFromStorage();
        if (cachedWallet) {
            this.currentWallet = cachedWallet;
            this.currentAccount = new Account(this.provider, cachedWallet.address, cachedWallet.privateKey);
            this.walletMode = 'oauth';
            await this.trackUsage(cachedWallet.address);
            return this.currentAccount;
        }

        // Fetch encrypted blob from API
        const walletData = await this.fetchWalletFromApi(user);

        if (!walletData) {
            throw new Error('No wallet found');
        }

        const { encrypted_pk_blob, address } = walletData;
        const [iv, ciphertext] = encrypted_pk_blob.split(':');

        if (!iv || !ciphertext) {
            throw new Error('Invalid encrypted blob format');
        }

        // Authenticate with Passkey
        const challenge = Crypto.getRandomBytes(32);
        const result = await this.passkeyManager.authenticate(challenge);

        // Decrypt private key
        const privateKey = await this.passkeyManager.decrypt(result.encryptionKey, ciphertext, iv);

        // Derive public key (getStarkKey accepts hex strings directly)
        const publicKey = ec.starkCurve.getStarkKey(privateKey);
        const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

        this.currentWallet = {
            address,
            publicKey: publicKeyHex,
            privateKey,
        };

        // Save to local storage
        await this.saveWalletToStorage(this.currentWallet);

        this.currentAccount = new Account(this.provider, address, privateKey);
        this.walletMode = 'oauth';

        await this.trackUsage(address);

        return this.currentAccount;
    }

    /**
     * Save wallet to SecureStore
     */
    private async saveWalletToStorage(wallet: DecryptedWallet): Promise<void> {
        try {
            await SecureStore.setItemAsync(
                NativeWalletManager.WALLET_STORAGE_KEY,
                JSON.stringify(wallet)
            );
        } catch (error) {
            console.warn('[NativeWalletManager] Failed to cache wallet:', error);
        }
    }

    /**
     * Load wallet from SecureStore
     */
    private async loadWalletFromStorage(): Promise<DecryptedWallet | null> {
        try {
            const data = await SecureStore.getItemAsync(NativeWalletManager.WALLET_STORAGE_KEY);
            if (!data) return null;
            return JSON.parse(data) as DecryptedWallet;
        } catch (error) {
            console.warn('[NativeWalletManager] Failed to load wallet from storage:', error);
            return null;
        }
    }

    /**
     * Clear wallet from storage
     */
    async clearWalletStorage(): Promise<void> {
        try {
            await SecureStore.deleteItemAsync(NativeWalletManager.WALLET_STORAGE_KEY);
        } catch (error) {
            console.warn('[NativeWalletManager] Failed to clear wallet storage:', error);
        }
    }

    /**
     * Save wallet to API
     */
    private async saveWalletToApi(user: UserInfo, address: string, encryptedBlob: string): Promise<void> {
        if (!this.accessToken) throw new Error('Not authenticated');

        await axios.post(`${this.backendUrl}/api/wallets`, {
            address,
            network: this.network,
            encrypted_pk_blob: encryptedBlob,
            app_id: this.appId,
            user_social_id: user.id,
            email: user.email,
        });
    }

    /**
     * Fetch wallet from API
     */
    private async fetchWalletFromApi(user: UserInfo): Promise<{ encrypted_pk_blob: string; address: string } | null> {
        if (!this.accessToken) throw new Error('Not authenticated');

        try {
            const params = new URLSearchParams({
                app_id: this.appId,
                user_social_id: user.id,
                network: this.network,
            });

            console.log('[NativeWalletManager] Fetching wallet from API:', {
                appId: this.appId,
                userSocialId: user.id,
                network: this.network,
                url: `${this.backendUrl}/api/wallets?${params.toString()}`,
            });

            const response = await axios.get(`${this.backendUrl}/api/wallets?${params.toString()}`);

            console.log('[NativeWalletManager] API response:', {
                found: response.data.found,
                hasAddress: !!response.data.address,
                hasEncryptedBlob: !!response.data.encrypted_pk_blob,
            });

            if (response.data.found) {
                return {
                    encrypted_pk_blob: response.data.encrypted_pk_blob,
                    address: response.data.address,
                };
            }
            return null;
        } catch (error) {
            console.error('[NativeWalletManager] Failed to fetch wallet:', error);
            return null;
        }
    }

    /**
     * Compute wallet address using ArgentX pattern
     */
    private async computeWalletAddress(publicKey: string): Promise<string> {
        const starkKeyPub = publicKey;
        const signer = new CairoCustomEnum({ Starknet: { pubkey: starkKeyPub } });
        const guardian = new CairoOption(1);
        const constructorCallData = CallData.compile({ owner: signer, guardian: guardian });

        return hash.calculateContractAddressFromHash(
            NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_OAUTH,
            NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_OAUTH,
            constructorCallData,
            0
        );
    }

    /**
     * Get deployment data for ArgentX account
     */
    getDeploymentData(): any {
        if (!this.currentWallet) throw new Error('No wallet initialized');

        const privateKey = this.currentWallet.privateKey;
        const starkKeyPub = ec.starkCurve.getStarkKey(privateKey);
        const signer = new CairoCustomEnum({ Starknet: { pubkey: starkKeyPub } });
        const guardian = new CairoOption(1);
        const constructorCallData = CallData.compile({ owner: signer, guardian: guardian });

        return {
            class_hash: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_OAUTH,
            salt: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_OAUTH,
            unique: '0x0',
            calldata: constructorCallData.map((x) => `0x${BigInt(x).toString(16)}`),
        };
    }

    /**
     * Check if account is deployed on-chain
     */
    async isDeployed(): Promise<boolean> {
        if (!this.currentWallet) return false;
        try {
            const classHash = await this.provider.getClassHashAt(this.currentWallet.address);
            return classHash !== '0x0' && classHash !== '0x' && classHash !== '';
        } catch {
            return false;
        }
    }

    /**
     * Deploy account with AVNU Paymaster
     */
    async deployAccountWithPaymaster(apiKey: string, network: 'mainnet' | 'sepolia' = 'sepolia'): Promise<string> {
        if (!this.currentWallet) throw new Error('No wallet initialized');
        if (await this.isDeployed()) {
            return this.currentWallet.address;
        }

        const userAddress = this.currentWallet.address;
        const deploymentData = this.getDeploymentData();

        const baseUrl = network === 'sepolia'
            ? 'https://sepolia.api.avnu.fi'
            : 'https://starknet.api.avnu.fi';

        // Build typed data
        await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'api-key': apiKey },
            body: JSON.stringify({
                userAddress,
                accountClassHash: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_OAUTH,
                deploymentData,
                calls: [],
            }),
        });

        // Deploy account
        const deployResponse = await fetch(`${baseUrl}/paymaster/v1/deploy-account`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'api-key': apiKey },
            body: JSON.stringify({ userAddress, deploymentData }),
        });

        if (!deployResponse.ok) throw new Error(await deployResponse.text());
        const deployResult = await deployResponse.json();

        if (deployResult.transactionHash) {
            await this.provider.waitForTransaction(deployResult.transactionHash);
        }

        return deployResult.transactionHash;
    }

    /**
     * Track MAU usage
     */
    private async trackUsage(walletAddress: string): Promise<void> {
        try {
            await axios.post(`${this.backendUrl}/api/usage/track`, {
                app_id: this.appId,
                wallet_address: walletAddress,
                network: this.network,
            });
        } catch (error) {
            console.debug('[Cavos Native SDK] Usage tracking failed:', error);
        }
    }

    /**
     * Check if passkeys are supported
     */
    async isPasskeySupported(): Promise<boolean> {
        return this.passkeyManager.isSupported();
    }

    /**
     * Check if wallet exists
     */
    async hasWallet(user: UserInfo): Promise<boolean> {
        const wallet = await this.fetchWalletFromApi(user);
        return wallet !== null;
    }

    getAccount(): Account | null {
        return this.currentAccount;
    }

    getAddress(): string | null {
        return this.currentWallet?.address || null;
    }

    getWalletInfo(): DecryptedWallet | null {
        return this.currentWallet;
    }

    getFundingAddress(): string | null {
        return this.currentWallet?.address || null;
    }

    async getBalance(): Promise<string> {
        if (!this.currentWallet) return '0';
        try {
            const ethAddress = '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
            const result = await this.provider.callContract({
                contractAddress: ethAddress,
                entrypoint: 'balanceOf',
                calldata: CallData.compile({ account: this.currentWallet.address }),
            });
            return Array.isArray(result) ? result[0] : '0';
        } catch {
            return '0';
        }
    }

    // ============================================
    // UNIFIED WALLET MODE GETTERS
    // ============================================

    getMode(): 'oauth' | 'passkey-only' | null {
        return this.walletMode;
    }

    isPasskeyOnlyMode(): boolean {
        return this.walletMode === 'passkey-only';
    }

    // ============================================
    // PASSKEY-ONLY WALLET METHODS
    // ============================================

    /**
     * Create a wallet using ONLY a passkey (FaceID/TouchID)
     * No OAuth login required. Wallet is stored locally.
     */
    async createPasskeyOnlyWallet(paymasterApiKey: string): Promise<void> {
        // 1. Register passkey with anonymous ID
        const { encryptionKey, credentialId } = await this.passkeyManager.registerAnonymous();

        // 2. Generate wallet keypair using 248-bit hex (valid for Stark curve)
        const privateKeyHex = `0x00${this.randomHex(62)}`;
        const publicKey = ec.starkCurve.getStarkKey(privateKeyHex);
        const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

        // 3. Compute wallet address
        const address = await this.computePasskeyWalletAddress(publicKeyHex);

        // 4. Encrypt private key
        const { ciphertext, iv } = await this.passkeyManager.encrypt(encryptionKey, privateKeyHex);

        // 5. Store locally using SecureStore
        await SecureStore.setItemAsync(
            NativeWalletManager.PASSKEY_WALLET_KEY,
            JSON.stringify({
                credentialId,
                address,
                publicKey: publicKeyHex,
                encryptedBlob: `${iv}:${ciphertext}`,
            })
        );

        // 6. Set wallet state
        this.currentWallet = {
            address,
            publicKey: publicKeyHex,
            privateKey: privateKeyHex,
        };
        this.currentAccount = new Account(this.provider, address, privateKeyHex);
        this.walletMode = 'passkey-only';

        // 7. Auto-deploy wallet
        await this.deployPasskeyWallet(paymasterApiKey);

        // 8. Save wallet to backend (for recovery with passkey)
        await this.savePasskeyWalletToBackend(credentialId, address, `${iv}:${ciphertext}`);

        // 9. Track usage
        await this.trackUsage(address);
    }

    /**
     * Load an existing passkey-only wallet
     * User will be prompted for FaceID/TouchID
     */
    async loadPasskeyOnlyWallet(): Promise<void> {
        // Get stored wallet data
        const dataStr = await SecureStore.getItemAsync(NativeWalletManager.PASSKEY_WALLET_KEY);
        if (!dataStr) {
            throw new Error('No passkey wallet found');
        }

        const data = JSON.parse(dataStr);

        // Authenticate with passkey (triggers FaceID/TouchID)
        const challenge = Crypto.getRandomBytes(32);
        const { encryptionKey } = await this.passkeyManager.authenticate(challenge);

        // Decrypt private key
        const [iv, ciphertext] = data.encryptedBlob.split(':');
        const privateKeyHex = await this.passkeyManager.decrypt(encryptionKey, ciphertext, iv);

        // Set wallet state
        this.currentWallet = {
            address: data.address,
            publicKey: data.publicKey,
            privateKey: privateKeyHex,
        };
        this.currentAccount = new Account(this.provider, data.address, privateKeyHex);
        this.walletMode = 'passkey-only';
    }

    /**
     * Recover wallet from backend using an existing passkey
     */
    async recoverWalletWithPasskey(): Promise<void> {
        // 1. Authenticate with passkey (user selects which passkey to use)
        const challenge = Crypto.getRandomBytes(32);
        const { encryptionKey, credentialId } = await this.passkeyManager.authenticate(challenge);

        // 2. Try to fetch wallet from backend using credentialId
        const backendWallet = await this.fetchPasskeyWalletFromBackend(credentialId);

        if (!backendWallet) {
            throw new Error('No wallet found in backend for this passkey.');
        }

        // 3. Decrypt private key
        const [iv, ciphertext] = backendWallet.encryptedBlob.split(':');
        const privateKeyHex = await this.passkeyManager.decrypt(encryptionKey, ciphertext, iv);

        // 4. Derive public key from private key
        const publicKey = ec.starkCurve.getStarkKey(privateKeyHex);
        const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

        // 5. Save to local storage for future use
        await SecureStore.setItemAsync(
            NativeWalletManager.PASSKEY_WALLET_KEY,
            JSON.stringify({
                credentialId,
                address: backendWallet.address,
                publicKey: publicKeyHex,
                encryptedBlob: backendWallet.encryptedBlob,
            })
        );

        // 6. Set wallet state
        this.currentWallet = {
            address: backendWallet.address,
            publicKey: publicKeyHex,
            privateKey: privateKeyHex,
        };
        this.currentAccount = new Account(this.provider, backendWallet.address, privateKeyHex);
        this.walletMode = 'passkey-only';

        console.log('[NativeWalletManager] Wallet recovered from backend successfully');
    }

    /**
     * Check if a passkey-only wallet exists locally
     */
    async hasPasskeyOnlyWallet(): Promise<boolean> {
        try {
            const data = await SecureStore.getItemAsync(NativeWalletManager.PASSKEY_WALLET_KEY);
            return data !== null;
        } catch {
            return false;
        }
    }

    /**
     * Clear passkey-only wallet from local storage
     */
    async clearPasskeyOnlyWallet(): Promise<void> {
        await SecureStore.deleteItemAsync(NativeWalletManager.PASSKEY_WALLET_KEY);
        if (this.walletMode === 'passkey-only') {
            this.currentWallet = null;
            this.currentAccount = null;
            this.walletMode = null;
        }
    }

    /**
     * Compute wallet address for passkey-only wallet
     * Using pow's proven deployment pattern
     */
    private async computePasskeyWalletAddress(publicKey: string): Promise<string> {
        const constructorCallData = CallData.compile({
            owner: publicKey,
            guardian: '0x0',
        });

        return hash.calculateContractAddressFromHash(
            publicKey,  // salt should be publicKey
            NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_PASSKEY,
            constructorCallData,
            0
        );
    }

    /**
     * Deploy passkey-only wallet via AVNU Paymaster
     */
    private async deployPasskeyWallet(paymasterApiKey: string): Promise<string> {
        if (!this.currentWallet) throw new Error('No passkey wallet');
        console.log('[NativeWalletManager] Starting wallet deployment...');

        // Build deployment data using pow's format
        const starkKeyPub = this.currentWallet.publicKey;
        const constructorCallData = CallData.compile({
            owner: starkKeyPub,
            guardian: '0x0',
        });

        const deploymentData = {
            class_hash: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_PASSKEY,
            salt: starkKeyPub,
            unique: '0x0',
            calldata: constructorCallData.map((x) => `0x${BigInt(x).toString(16)}`),
        };

        const baseUrl = this.network === 'sepolia'
            ? 'https://sepolia.api.avnu.fi'
            : 'https://starknet.api.avnu.fi';

        try {
            // Step 1: Build typed data
            console.log('[NativeWalletManager] Building typed data...');
            const typeDataResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': paymasterApiKey,
                },
                body: JSON.stringify({
                    userAddress: this.currentWallet.address,
                    accountClassHash: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH_PASSKEY,
                    deploymentData: deploymentData,
                    calls: [],
                }),
            });

            if (!typeDataResponse.ok) {
                const errorText = await typeDataResponse.text();
                console.error('[NativeWalletManager] Build typed data failed:', errorText);
                throw new Error(errorText);
            }

            // Step 2: Deploy account
            console.log('[NativeWalletManager] Deploying account...');
            const deployResponse = await fetch(`${baseUrl}/paymaster/v1/deploy-account`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': paymasterApiKey,
                },
                body: JSON.stringify({
                    userAddress: this.currentWallet.address,
                    deploymentData,
                }),
            });

            if (!deployResponse.ok) {
                const errorText = await deployResponse.text();
                console.error('[NativeWalletManager] Deploy failed:', errorText);
                throw new Error(errorText);
            }

            const deployResult = await deployResponse.json();
            console.log('[NativeWalletManager] Deploy result:', JSON.stringify(deployResult));

            if (deployResult.transactionHash) {
                console.log('[NativeWalletManager] Waiting for transaction:', deployResult.transactionHash);
                await this.provider.waitForTransaction(deployResult.transactionHash);
                console.log('[NativeWalletManager] Account deployed successfully!');
            }

            return deployResult.transactionHash;
        } catch (error: any) {
            console.error('[NativeWalletManager] Deployment error:', error.message || error);
            if (error.message?.includes('already deployed') || error.message?.includes('CONTRACT_ADDRESS_UNAVAILABLE')) {
                console.log('[NativeWalletManager] Account already deployed');
                return this.currentWallet.address;
            }
            throw error;
        }
    }

    /**
     * Save passkey wallet to backend for recovery
     */
    private async savePasskeyWalletToBackend(
        credentialId: string,
        address: string,
        encryptedBlob: string
    ): Promise<void> {
        try {
            const response = await fetch(`${this.backendUrl}/api/wallets`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    app_id: this.appId,
                    user_social_id: `passkey:${credentialId}`,
                    network: this.network,
                    address,
                    encrypted_pk_blob: encryptedBlob,
                }),
            });

            if (!response.ok) {
                console.warn('[NativeWalletManager] Failed to save wallet to backend');
            } else {
                console.log('[NativeWalletManager] Wallet saved to backend for recovery');
            }
        } catch (error) {
            console.warn('[NativeWalletManager] Error saving wallet to backend:', error);
        }
    }

    /**
     * Fetch passkey wallet from backend for recovery
     */
    private async fetchPasskeyWalletFromBackend(
        credentialId: string
    ): Promise<{ address: string; encryptedBlob: string } | null> {
        try {
            const params = new URLSearchParams({
                app_id: this.appId,
                user_social_id: `passkey:${credentialId}`,
                network: this.network,
            });

            const response = await fetch(`${this.backendUrl}/api/wallets?${params.toString()}`);

            if (!response.ok) return null;

            const data = await response.json();

            if (data.found && data.encrypted_pk_blob && data.address) {
                return { address: data.address, encryptedBlob: data.encrypted_pk_blob };
            }

            return null;
        } catch (error) {
            console.warn('[NativeWalletManager] Error fetching wallet from backend:', error);
            return null;
        }
    }
}
