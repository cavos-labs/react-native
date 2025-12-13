/**
 * NativePasskeyManager handles Passkey operations for React Native.
 * 
 * Uses:
 * - react-native-passkey for native passkey operations
 * - expo-crypto for random bytes and hashing
 * - @noble/ciphers for AES-GCM encryption (expo-crypto doesn't support it)
 */

import { PasskeyResult } from '../types';
import * as Crypto from 'expo-crypto';
import { gcm } from '@noble/ciphers/aes.js';

/**
 * Result from passkey registration
 */
export interface PasskeyRegistrationResult {
    encryptionKey: CryptoKeyLike;
    credentialId: string;
}

// Passkey module will be dynamically imported
let Passkey: any = null;

export class NativePasskeyManager {
    private rpId: string;
    private static readonly RP_NAME = 'Cavos Wallet';
    private static readonly PRF_SALT = new Uint8Array(32).fill(1);

    constructor(rpId: string) {
        this.rpId = rpId;
    }

    /**
     * Initialize passkey dependency
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
     * @returns Encryption key and credential ID
     */
    async register(userId: string, challenge: Uint8Array): Promise<PasskeyRegistrationResult> {
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
        const encryptionKey = await this.deriveKeyFromCredential(result);

        return {
            encryptionKey,
            credentialId: result.rawId,
        };
    }

    /**
     * Register a passkey with auto-generated anonymous userId
     * For passkey-only wallet creation (no OAuth required)
     */
    async registerAnonymous(): Promise<PasskeyRegistrationResult> {
        // Generate a random UUID as the anonymous userId
        const anonymousId = Crypto.randomUUID();
        const challenge = Crypto.getRandomBytes(32);

        return this.register(anonymousId, challenge);
    }

    /**
     * Register a new Passkey with provided userId (legacy method for compatibility)
     * Returns only CryptoKeyLike for backward compatibility
     */
    async registerLegacy(userId: string, challenge: Uint8Array): Promise<CryptoKeyLike> {
        const result = await this.register(userId, challenge);
        return result.encryptionKey;
    }

    /**
     * Authenticate with existing Passkey and derive the same encryption key
     * @param challenge Random challenge for authentication
     * @returns Encryption key and credential ID
     */
    async authenticate(challenge: Uint8Array): Promise<PasskeyRegistrationResult> {
        await this.ensureDependencies();

        const challengeB64 = this.arrayBufferToBase64url(challenge.buffer as ArrayBuffer);

        const result: PasskeyResult = await Passkey.authenticate({
            challenge: challengeB64,
            rpId: this.rpId,
            userVerification: 'required',
        });

        // Derive encryption key from credential data
        const encryptionKey = await this.deriveKeyFromCredential(result);

        return {
            encryptionKey,
            credentialId: result.rawId,
        };
    }

    /**
     * Derive a stable encryption key from passkey credential
     * Uses HMAC-SHA256 via expo-crypto
     */
    private async deriveKeyFromCredential(result: PasskeyResult): Promise<CryptoKeyLike> {
        // Combine credential ID and salt for key derivation
        const credentialIdBytes = new Uint8Array(this.base64urlToArrayBuffer(result.rawId));
        const inputKeyMaterial = new Uint8Array(credentialIdBytes.byteLength + NativePasskeyManager.PRF_SALT.length);
        inputKeyMaterial.set(credentialIdBytes, 0);
        inputKeyMaterial.set(NativePasskeyManager.PRF_SALT, credentialIdBytes.byteLength);

        // Use SHA256 to derive a 256-bit key (expo-crypto)
        const derivedKeyBuffer = await Crypto.digest(
            Crypto.CryptoDigestAlgorithm.SHA256,
            inputKeyMaterial
        );

        return {
            rawKey: new Uint8Array(derivedKeyBuffer),
            algorithm: 'AES-GCM',
        };
    }

    /**
     * Encrypt data using AES-256-GCM
     */
    async encrypt(key: CryptoKeyLike, data: string): Promise<{ ciphertext: string; iv: string }> {
        const iv = Crypto.getRandomBytes(12); // 96-bit IV for AES-GCM
        const dataBytes = new TextEncoder().encode(data);

        const aes = gcm(key.rawKey, iv);
        const encrypted = aes.encrypt(dataBytes);

        return {
            ciphertext: this.uint8ArrayToBase64(encrypted),
            iv: this.uint8ArrayToBase64(iv),
        };
    }

    /**
     * Decrypt data using AES-256-GCM
     */
    async decrypt(key: CryptoKeyLike, ciphertext: string, iv: string): Promise<string> {
        const ivBytes = this.base64ToUint8Array(iv);
        const encryptedBytes = this.base64ToUint8Array(ciphertext);

        const aes = gcm(key.rawKey, ivBytes);
        const decrypted = aes.decrypt(encryptedBytes);

        return new TextDecoder().decode(decrypted);
    }

    // Helper: Uint8Array to Base64
    private uint8ArrayToBase64(bytes: Uint8Array): string {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // Helper: Base64 to Uint8Array
    private base64ToUint8Array(base64: string): Uint8Array {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // Helper: ArrayBuffer to Base64URL
    private arrayBufferToBase64url(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return this.base64ToBase64url(btoa(binary));
    }

    // Helper: Base64URL to ArrayBuffer
    private base64urlToArrayBuffer(base64url: string): ArrayBuffer {
        const base64 = this.base64urlToBase64(base64url);
        const binary = atob(base64);
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
 * Uses Uint8Array instead of Buffer for compatibility
 */
export interface CryptoKeyLike {
    rawKey: Uint8Array;
    algorithm: string;
}
