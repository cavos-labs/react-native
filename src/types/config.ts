import type { PasskeyModalConfig } from './modal';

export interface CavosNativeConfig {
    /** Your app ID from Cavos dashboard (https://cavos.xyz/dashboard) */
    appId: string;

    /**
     * The Relying Party ID for passkey operations.
     * This MUST match the domain where web passkeys were created
     * to enable cross-platform wallet access.
     * 
     * Example: 'cavos.xyz' or 'yourapp.com'
     */
    rpId: string;

    /** Backend URL for OAuth orchestration (default: https://cavos.xyz) */
    backendUrl?: string;
    /** StarkNet RPC URL (optional, uses default if not provided) */
    starknetRpcUrl?: string;
    /** Network to use (default: sepolia) */
    network?: 'mainnet' | 'sepolia';
    /** AVNU Paymaster API key for gasless transactions (optional, uses Cavos shared key if not provided) */
    paymasterApiKey?: string;
    /** Enable debug logging (default: false) */
    enableLogging?: boolean;
    /** Passkey modal configuration */
    passkeyModal?: PasskeyModalConfig;
}

export interface AuthConfig {
    backendUrl: string;
    appId: string;
}
