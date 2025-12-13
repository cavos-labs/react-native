import { useCavosNative } from '../CavosNativeContext';

export function useAuth() {
    const { isAuthenticated, user, logout, isLoading } = useCavosNative();

    return {
        isAuthenticated,
        user,
        logout,
        isLoading,
    };
}
