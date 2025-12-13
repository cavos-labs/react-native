/**
 * NativePasskeyManager handles Passkey operations for React Native.
 * 
 * Key difference from WebAuthnManager:
 * - Uses configurable RP ID instead of window.location.hostname
 * - Uses react-native-passkey for native operations
 * - Uses react-native-quick-crypto for AES-GCM encryption
 */

import { PasskeyResult } from '../types';

// These will be dynamically imported to avoid bundling issues
let Passkey: any = null;
let QuickCrypto: any = null;

export class NativePasskeyManager {
    private rpId: string;
    private static readonly RP_NAME = 'Cavos Wallet';
    private static readonly PRF_SALT = new Uint8Array(32).fill(1);

    constructor(rpId: string) {
        this.rpId = rpId;
    }

    /**
     * Initialize native dependencies
     */
    private async ensureDependencies(): Promise<void> {
        if (!Passkey) {
            try {
                const passkeyModule = require('react-native-passkey');
                Passkey = passkeyModule.Passkey || passkeyModule.default;
            } catch (e) {
                throw new Error(
                    'react-native-passkey is required. Install it with: npm install react-native-passkey'
                );
            }
        }

        if (!QuickCrypto) {
            try {
                const cryptoModule = require('react-native-quick-crypto');
                QuickCrypto = cryptoModule.default || cryptoModule;
            } catch (e) {
                throw new Error(
                    'react-native-quick-crypto is required. Install it with: npm install react-native-quick-crypto'
                );
            }
        }
    }

    /**
     * Check if passkeys are supported on this device
     */
    async isSupported(): Promise<boolean> {
        try {
            await this.ensureDependencies();
            return await Passkey.isSupported();
        } catch {
            return false;
        }
    }

    /**
     * Register a new Passkey and derive an encryption key
     * @param userId User's unique identifier (e.g. email or social ID)
     * @param challenge Random challenge for registration
     */
    async register(userId: string, challenge: Uint8Array): Promise<CryptoKeyLike> {
        await this.ensureDependencies();

        const challengeB64 = this.arrayBufferToBase64url(challenge.buffer as ArrayBuffer);
        const userIdB64 = this.arrayBufferToBase64url(new TextEncoder().encode(userId).buffer as ArrayBuffer);

        const result: PasskeyResult = await Passkey.register({
            challenge: challengeB64,
            rp: {
                id: this.rpId,
                name: NativePasskeyManager.RP_NAME,
            },
            user: {
                id: userIdB64,
                name: userId,
                displayName: userId,
            },
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                requireResidentKey: true,
                userVerification: 'required',
            },
            pubKeyCredParams: [
                { alg: -7, type: 'public-key' },   // ES256
                { alg: -257, type: 'public-key' }, // RS256
            ],
        });

        // Derive encryption key from credential data
        return this.deriveKeyFromCredential(result);
    }

    /**
     * Authenticate with existing Passkey and derive the same encryption key
     * @param challenge Random challenge for authentication
     */
    async authenticate(challenge: Uint8Array): Promise<CryptoKeyLike> {
        await this.ensureDependencies();

        const challengeB64 = this.arrayBufferToBase64url(challenge.buffer as ArrayBuffer);

        const result: PasskeyResult = await Passkey.authenticate({
            challenge: challengeB64,
            rpId: this.rpId,
            userVerification: 'required',
        });

        // Derive encryption key from credential data
        return this.deriveKeyFromCredential(result);
    }

    /**
     * Derive a stable encryption key from passkey credential
     * Since PRF extension may not be available on all native platforms,
     * we use HKDF with the credential ID and authenticator data as input
     */
    private async deriveKeyFromCredential(result: PasskeyResult): Promise<CryptoKeyLike> {
        await this.ensureDependencies();

        // Combine credential ID and salt for key derivation
        const credentialIdBytes = this.base64urlToArrayBuffer(result.rawId);
        const inputKeyMaterial = new Uint8Array(credentialIdBytes.byteLength + NativePasskeyManager.PRF_SALT.length);
        inputKeyMaterial.set(new Uint8Array(credentialIdBytes), 0);
        inputKeyMaterial.set(NativePasskeyManager.PRF_SALT, credentialIdBytes.byteLength);

        // Use HKDF to derive a 256-bit key
        const derivedKey = QuickCrypto.createHmac('sha256', NativePasskeyManager.PRF_SALT)
            .update(Buffer.from(inputKeyMaterial))
            .digest();

        return {
            rawKey: derivedKey,
            algorithm: 'AES-GCM',
        };
    }

    /**
     * Encrypt data using the derived key
     */
    async encrypt(key: CryptoKeyLike, data: string): Promise<{ ciphertext: string; iv: string }> {
        await this.ensureDependencies();

        const iv = QuickCrypto.randomBytes(12); // 96-bit IV for AES-GCM
        const cipher = QuickCrypto.createCipheriv('aes-256-gcm', key.rawKey, iv);

        let encrypted = cipher.update(data, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const authTag = cipher.getAuthTag();

        // Combine ciphertext and auth tag
        const combined = Buffer.concat([encrypted, authTag]);

        return {
            ciphertext: combined.toString('base64'),
            iv: iv.toString('base64'),
        };
    }

    /**
     * Decrypt data using the derived key
     */
    async decrypt(key: CryptoKeyLike, ciphertext: string, iv: string): Promise<string> {
        await this.ensureDependencies();

        const ivBuffer = Buffer.from(iv, 'base64');
        const combined = Buffer.from(ciphertext, 'base64');

        // Extract auth tag (last 16 bytes)
        const authTag = combined.slice(-16);
        const encryptedData = combined.slice(0, -16);

        const decipher = QuickCrypto.createDecipheriv('aes-256-gcm', key.rawKey, ivBuffer);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedData);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString('utf8');
    }

    // Helper: ArrayBuffer to Base64URL
    private arrayBufferToBase64url(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return this.base64ToBase64url(Buffer.from(binary, 'binary').toString('base64'));
    }

    // Helper: Base64URL to ArrayBuffer
    private base64urlToArrayBuffer(base64url: string): ArrayBuffer {
        const base64 = this.base64urlToBase64(base64url);
        const binary = Buffer.from(base64, 'base64').toString('binary');
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    private base64ToBase64url(base64: string): string {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    private base64urlToBase64(base64url: string): string {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        return base64;
    }
}

/**
 * CryptoKey-like interface for React Native
 * Since we can't use Web Crypto API, we use this structure
 */
export interface CryptoKeyLike {
    rawKey: Buffer;
    algorithm: string;
}
