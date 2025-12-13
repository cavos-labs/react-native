import { Account, Call } from 'starknet';

export class PaymasterIntegration {
    private apiKey: string | null = null;
    private enabled: boolean = false;
    private network: 'mainnet' | 'sepolia';

    constructor(apiKey?: string, network: 'mainnet' | 'sepolia' = 'sepolia') {
        this.network = network;
        if (apiKey) {
            this.apiKey = apiKey;
            this.enabled = true;
        }
    }

    /**
     * Check if gasless transactions are available
     */
    isGaslessAvailable(): boolean {
        return this.enabled && this.apiKey !== null;
    }

    /**
     * Execute gasless transaction using AVNU Paymaster
     */
    async executeGasless(calls: Call | Call[], account: Account): Promise<string> {
        if (!this.apiKey) {
            throw new Error('Paymaster API key not configured');
        }

        const callsArray = Array.isArray(calls) ? calls : [calls];
        const baseUrl = this.network === 'sepolia'
            ? 'https://sepolia.api.avnu.fi'
            : 'https://starknet.api.avnu.fi';

        try {
            // Build typed data
            const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.apiKey,
                },
                body: JSON.stringify({
                    userAddress: account.address,
                    calls: callsArray.map(call => ({
                        contractAddress: call.contractAddress,
                        entrypoint: call.entrypoint,
                        calldata: call.calldata || [],
                    })),
                }),
            });

            if (!buildResponse.ok) {
                throw new Error(await buildResponse.text());
            }

            const typedData = await buildResponse.json();

            // Sign
            const signature = await account.signMessage(typedData.typedData);

            // Execute
            const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.apiKey,
                },
                body: JSON.stringify({
                    userAddress: account.address,
                    typedData: typedData.typedData,
                    signature: Array.isArray(signature) ? signature : [signature.r, signature.s],
                }),
            });

            if (!executeResponse.ok) {
                throw new Error(await executeResponse.text());
            }

            const result = await executeResponse.json();
            return result.transactionHash;
        } catch (error: any) {
            console.error('[PaymasterIntegration] Gasless execution failed:', error);
            throw new Error(`Gasless transaction failed: ${error.message}`);
        }
    }

    /**
     * Estimate if transaction is eligible for gasless execution
     */
    async isEligibleForGasless(_calls: Call | Call[], _account: Account): Promise<boolean> {
        if (!this.apiKey) {
            return false;
        }
        // For now, assume all transactions are eligible
        // Could add quota checking here
        return true;
    }

    /**
     * Set API key
     */
    setApiKey(apiKey: string): void {
        this.apiKey = apiKey;
        this.enabled = true;
    }

    /**
     * Set network
     */
    setNetwork(network: 'mainnet' | 'sepolia'): void {
        this.network = network;
    }

    /**
     * Disable gasless transactions
     */
    disable(): void {
        this.enabled = false;
    }

    /**
     * Enable gasless transactions
     */
    enable(): void {
        if (this.apiKey) {
            this.enabled = true;
        } else {
            throw new Error('Cannot enable gasless without API key');
        }
    }
}
