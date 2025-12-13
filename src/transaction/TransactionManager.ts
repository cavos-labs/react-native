import { Account, Call } from 'starknet';
import { AnalyticsManager } from '../analytics/AnalyticsManager';

export interface ExecuteOptions {
    gasless?: boolean;
}

export class TransactionManager {
    private account: Account;
    private paymasterApiKey: string;
    private network: 'mainnet' | 'sepolia';
    private analyticsManager: AnalyticsManager | null = null;

    constructor(
        account: Account,
        paymasterApiKey: string,
        network: 'mainnet' | 'sepolia' = 'sepolia',
        analyticsManager?: AnalyticsManager
    ) {
        this.account = account;
        this.paymasterApiKey = paymasterApiKey;
        this.network = network;
        if (analyticsManager) {
            this.analyticsManager = analyticsManager;
        }
    }

    async execute(calls: Call | Call[], options?: ExecuteOptions): Promise<string> {
        const callsArray = Array.isArray(calls) ? calls : [calls];

        if (options?.gasless) {
            return this.executeGasless(callsArray);
        }

        // Regular execution (user pays gas)
        const result = await this.account.execute(callsArray);
        return result.transaction_hash;
    }

    private async executeGasless(calls: Call[]): Promise<string> {
        try {
            const baseUrl = this.network === 'sepolia'
                ? 'https://sepolia.api.avnu.fi'
                : 'https://starknet.api.avnu.fi';

            // Step 1: Build typed data
            const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.paymasterApiKey,
                },
                body: JSON.stringify({
                    userAddress: this.account.address,
                    calls: calls.map(call => ({
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

            // Step 2: Sign the typed data
            const signature = await this.account.signMessage(typedData.typedData);

            // Step 3: Execute via paymaster
            const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.paymasterApiKey,
                },
                body: JSON.stringify({
                    userAddress: this.account.address,
                    typedData: typedData.typedData,
                    signature: Array.isArray(signature) ? signature : [signature.r, signature.s],
                }),
            });

            if (!executeResponse.ok) {
                throw new Error(await executeResponse.text());
            }

            const result = await executeResponse.json();

            // Track transaction analytics
            if (this.analyticsManager) {
                await this.analyticsManager.trackTransaction(
                    result.transactionHash,
                    this.account.address,
                    'pending'
                );
            }

            return result.transactionHash;
        } catch (error: any) {
            console.error('[TransactionManager] Gasless execution failed:', error);
            throw new Error(`Failed to execute gasless transaction: ${error.message || error}`);
        }
    }
}
