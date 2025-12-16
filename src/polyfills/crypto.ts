/**
 * Crypto polyfill for React Native
 * This must be imported BEFORE any other modules that use crypto
 * (like starknet, @noble/curves, @noble/hashes)
 */
import * as ExpoCrypto from 'expo-crypto';

// Setup crypto polyfill immediately
if (typeof global !== 'undefined') {
    // Create crypto object if it doesn't exist
    if (!(global as any).crypto) {
        (global as any).crypto = {} as Crypto;
    }

    // Polyfill getRandomValues using expo-crypto
    if (!(global as any).crypto.getRandomValues) {
        (global as any).crypto.getRandomValues = <T extends ArrayBufferView | null>(array: T): T => {
            if (array === null) return array;
            const bytes = ExpoCrypto.getRandomBytes(array.byteLength);
            const uint8Array = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
            uint8Array.set(bytes);
            return array;
        };
    }
}

// Export nothing, this module is just for side effects
export { };
