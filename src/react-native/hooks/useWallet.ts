import { useCavosNative } from '../CavosNativeContext';

export function useWallet() {
    const { address, isAuthenticated, user } = useCavosNative();

    return {
        address,
        isConnected: isAuthenticated,
        user,
    };
}
