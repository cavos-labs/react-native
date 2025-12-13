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

    // ArgentX account class hash (v0.3.0)
    private static readonly ARGENT_ACCOUNT_CLASS_HASH = '0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f';

    // Storage keys
    private static readonly WALLET_STORAGE_KEY = '@cavos/wallet_session';

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
     * Create a new wallet with native Passkey encryption
     */
    async createWallet(user: UserInfo): Promise<Account> {
        this.userEmail = user.email;

        // 1. Generate new keypair
        const privateKey = ec.starkCurve.utils.randomPrivateKey();
        const publicKey = ec.starkCurve.getStarkKey(privateKey);

        // 2. Compute wallet address
        const address = await this.computeWalletAddress(publicKey);

        const privateKeyHex = '0x' + Buffer.from(privateKey).toString('hex');
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

        // Derive public key
        const privateKeyBytes = Buffer.from(privateKey.replace('0x', ''), 'hex');
        const publicKey = ec.starkCurve.getStarkKey(privateKeyBytes);
        const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

        this.currentWallet = {
            address,
            publicKey: publicKeyHex,
            privateKey,
        };

        // Save to local storage
        await this.saveWalletToStorage(this.currentWallet);

        this.currentAccount = new Account(this.provider, address, privateKey);

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

            const response = await axios.get(`${this.backendUrl}/api/wallets?${params.toString()}`);

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
            NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH,
            NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH,
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
            class_hash: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH,
            salt: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH,
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
                accountClassHash: NativeWalletManager.ARGENT_ACCOUNT_CLASS_HASH,
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
}
