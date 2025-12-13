export * from './config';
export * from './session';
export * from './wallet';
export * from './storage';
export * from './auth';
export * from './modal';

// Signature types
export interface TypedData {
    types: Record<string, Array<{ name: string; type: string }>>;
    primaryType: string;
    domain: {
        name?: string;
        version?: string;
        chainId?: string | number;
        verifyingContract?: string;
    };
    message: Record<string, any>;
}

export interface Signature {
    r: string;
    s: string;
    recovery_id?: number;
}
