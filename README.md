# @cavos/react-native

Cavos SDK for React Native - Invisible crypto infrastructure with native passkeys.

## Features

- Native Passkey (FaceID/TouchID) authentication
- Non-custodial wallet management
- Gasless transactions via AVNU Paymaster
- Cross-platform passkey support (share wallets between web and mobile)
- Same API as `@cavos/react`

## Installation

```bash
npm install @cavos/react-native

# Required peer dependencies
npm install react-native-passkey react-native-quick-crypto @react-native-async-storage/async-storage

```

## Platform Configuration

### iOS Setup

1. Add Associated Domains capability in Xcode
2. Add your domain to the entitlements:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>webcredentials:YOUR_DOMAIN.com</string>
</array>
```

3. Host the Apple App Site Association file at `https://YOUR_DOMAIN.com/.well-known/apple-app-site-association`:

```json
{
  "webcredentials": {
    "apps": ["TEAM_ID.com.yourapp.bundleid"]
  }
}
```

### Android Setup

1. Host the Asset Links file at `https://YOUR_DOMAIN.com/.well-known/assetlinks.json`:

```json
[{
  "relation": ["delegate_permission/common.get_login_creds"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.yourapp",
    "sha256_cert_fingerprints": ["YOUR_SHA256_FINGERPRINT"]
  }
}]
```

## Usage

### Basic Setup

```tsx
import { CavosNativeProvider, useCavos } from '@cavos/react-native';

export default function App() {
  return (
    <CavosNativeProvider
      appId="your-app-id"
      rpId="yourapp.com"  // Must match your web domain!
      network="mainnet"
    >
      <WalletScreen />
    </CavosNativeProvider>
  );
}
```

### Authentication

```tsx
import { useCavos } from '@cavos/react-native';
import { Linking } from 'react-native';

function LoginScreen() {
  const { getLoginUrl, setAuthData, isAuthenticated } = useCavos();

  const handleLogin = async () => {
    // Get OAuth URL
    const url = await getLoginUrl('google', 'yourapp://auth/callback');
    
    // Open in browser
    await Linking.openURL(url);
  };

  // Handle deep link callback in your app
  const handleAuthCallback = async (authData) => {
    await setAuthData(authData);
  };

  return (
    <Button onPress={handleLogin} title="Login with Google" />
  );
}
```

### Wallet Operations

```tsx
import { useCavos } from '@cavos/react-native';

function WalletScreen() {
  const {
    address,
    isLoading,
    requiresWalletCreation,
    createWallet,
    execute,
    getBalance,
  } = useCavos();

  // Create wallet (triggers FaceID/TouchID)
  const handleCreateWallet = async () => {
    await createWallet();
  };

  // Execute transaction (gasless by default)
  const handleTransfer = async () => {
    const txHash = await execute({
      contractAddress: '0x...',
      entrypoint: 'transfer',
      calldata: ['0x...', '1000000000000000000'],
    });
    console.log('Transaction:', txHash);
  };

  if (requiresWalletCreation) {
    return <Button onPress={handleCreateWallet} title="Setup Wallet" />;
  }

  return (
    <View>
      <Text>Address: {address}</Text>
      <Button onPress={handleTransfer} title="Send Transaction" />
    </View>
  );
}
```

## Cross-Platform Wallet Sharing

To use the same wallet across web and mobile:

1. **Web App**: User creates wallet on `yourapp.com`
2. **Mobile App**: Configure `rpId: 'yourapp.com'`
3. **Platform Config**: Set up Associated Domains (iOS) and Asset Links (Android)

The passkey created on web will be available on mobile via iCloud Keychain (iOS) or Google Password Manager (Android).

## API Reference

### CavosNativeProvider Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `appId` | `string` | Yes | Your Cavos App ID |
| `rpId` | `string` | Yes | Relying Party ID (your domain) |
| `network` | `'mainnet' \| 'sepolia'` | No | Starknet network (default: 'sepolia') |
| `paymasterApiKey` | `string` | No | Custom paymaster API key |

### useCavos() Hook

```typescript
{
  // State
  isInitialized: boolean;
  isLoading: boolean;
  isAuthenticated: boolean;
  address: string | null;
  user: UserInfo | null;
  error: Error | null;
  requiresWalletCreation: boolean;

  // Methods
  getLoginUrl(provider, redirectUri): Promise<string>;
  setAuthData(authData): Promise<void>;
  logout(): Promise<void>;
  createWallet(): Promise<void>;
  retryWalletUnlock(): Promise<void>;
  execute(calls, options?): Promise<string>;
  getBalance(): Promise<string>;
  getOnramp(provider): string;
  isPasskeySupported(): Promise<boolean>;
}
```

## Requirements

- iOS 15.0+
- Android API 28+
- React Native 0.72+

## License

MIT
