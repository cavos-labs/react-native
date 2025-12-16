# @cavos/react-native

A library to add secure, easy-to-use wallets to your React Native (Expo) application.

It lets your users log in with Google or Apple and creates a secure wallet for them. They do not need to worry about private keys or seed phrases.

## Why use this?

*   **Easy Login:** Users sign in with their existing Google or Apple accounts.
*   **Secure:** The private keys are created on the user's device, encrypted with their passkeys (FaceID/TouchID) which generates a blob saved on our platform for the user to restore it. Only the user can access their wallet.
*   **Free Transactions:** We pay the gas fees for your users, so they do not need to buy ETH or STRK to start using your app.
*   **Works Everywhere:** Users can access their wallet from any device by logging in.

## Installation

Run this command in your project folder:

```bash
npm install @cavos/react-native starknet react-native-passkey expo-secure-store expo-crypto
```

> **Note:** This SDK is designed for Expo environments (managed or bare). Ensure you have configured `react-native-passkey` correctly for your platform (iOS/Android).

## How to use it

### 1. Setup

Wrap your application with the `CavosNativeProvider`. This makes the wallet features available throughout your app.

```tsx
import { CavosNativeProvider } from '@cavos/react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <CavosNativeProvider
        config={{
          appId: 'your-app-id', // Get this from your Cavos dashboard
          rpId: 'app.yourdomain.com', // REQUIRED: Your associated domain for Passkeys
          network: 'sepolia', // Use 'mainnet' or 'sepolia'
        }}
      >
        <Stack />
      </CavosNativeProvider>
    </SafeAreaProvider>
  );
}
```

### 2. Login Buttons

Add buttons to let users log in.

```tsx
import { useCavosNative } from '@cavos/react-native';
import { View, TouchableOpacity, Text } from 'react-native';

function LoginScreen() {
  const { login, isAuthenticated, user, createWallet } = useCavosNative();

  if (isAuthenticated) {
    return <Text>Hello, {user?.email}!</Text>;
  }

  return (
    <View>
      <TouchableOpacity onPress={() => login('google')}>
        <Text>Login with Google</Text>
      </TouchableOpacity>
        
      <TouchableOpacity onPress={() => login('apple')}>
        <Text>Login with Apple</Text>
      </TouchableOpacity>

      {/* Passkey-Only Option */}
      <TouchableOpacity onPress={createWallet}>
         <Text>Continue with Passkey</Text>
      </TouchableOpacity>
    </View>
  );
}
```

### 3. Creating the Wallet

After logging in (or if using Passkey-only mode), the user needs to create their wallet. This happens automatically with a secure passkey (FaceID or TouchID). 

The `createWallet` function handles the entire flow:
1. If logged in with OAuth: Creates a wallet linked to the social account.
2. If NOT logged in: Attempts to recover an existing passkey wallet; if none found, creates a new one.

### 4. Sending Transactions

You can send transactions on the blockchain easily.

```tsx
import { useCavosNative } from '@cavos/react-native';

function SendMoney() {
  const { execute } = useCavosNative();

  const handleSend = async () => {
    try {
      const transactionHash = await execute(
        {
          contractAddress: '0x...', 
          entrypoint: 'transfer', 
          calldata: ['0x...', '1000', '0'],
        },
        { gasless: true } 
      );
      console.log('Transaction hash:', transactionHash);
    } catch (error) {
      console.error('Transaction failed:', error);
    }
  };

  return (
    <TouchableOpacity onPress={handleSend}>
      <Text>Send Transaction</Text>
    </TouchableOpacity>
  );
}
```

### 5. Buying Crypto (Onramp)

You can let users buy crypto with their credit card. *Note: React Native implementation may vary depending on deep linking setup.*

```tsx
import { useCavosNative } from '@cavos/react-native';
import * as Linking from 'expo-linking';

function BuyCrypto() {
  const { getOnramp } = useCavosNative();

  const handleBuy = async () => {
    try {
      const url = getOnramp('RAMP_NETWORK');
      await Linking.openURL(url);
    } catch (error) {
      console.error('Error:', error);
    }
  };
}
```

### 6. Handling Wallet Unlock Errors

If a user cancels the passkey prompt, you can allow them to retry.

```tsx
import { useCavosNative } from '@cavos/react-native';

function WalletStatus() {
  const { isAuthenticated, address, retryWalletUnlock } = useCavosNative();

  if (isAuthenticated && !address) {
    return (
      <View>
        <Text>Your wallet needs to be unlocked.</Text>
        <TouchableOpacity onPress={() => retryWalletUnlock()}>
           <Text>Unlock Wallet</Text>
        </TouchableOpacity>
      </View>
    );
  }
}
```

### 7. Account Deletion

Allow users to delete their account.

```tsx
const { deleteAccount } = useCavosNative();
// ...
await deleteAccount();
```

For advanced usage (Signature, Custom RPC, Paymasters), see [ADVANCED.md](./ADVANCED.md).
