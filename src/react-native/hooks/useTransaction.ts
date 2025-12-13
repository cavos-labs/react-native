import { useState } from 'react';
import { Call } from 'starknet';
import { useCavosNative } from '../CavosNativeContext';

type ExecuteOptions = { gasless?: boolean };

export function useTransaction() {
    const { execute } = useCavosNative();
    const [isSending, setIsSending] = useState(false);
    const [error, setError] = useState<Error | null>(null);
    const [txHash, setTxHash] = useState<string | null>(null);

    const sendTransaction = async (calls: Call | Call[], options?: ExecuteOptions) => {
        setIsSending(true);
        setError(null);
        setTxHash(null);

        try {
            const hash = await execute(calls, options);
            setTxHash(hash);
            return hash;
        } catch (err) {
            setError(err as Error);
            throw err;
        } finally {
            setIsSending(false);
        }
    };

    return {
        sendTransaction,
        isSending,
        error,
        txHash,
    };
}
