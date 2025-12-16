# Advanced Specification (@cavos/react-native)

## Domain Association & rpId Configuration

Passkeys in mobile apps rely on **Domain Association**. This connects your native mobile app to a specific web domain (your `rpId`), proving that you own both. This is required by Apple and Google for security.

### What is `rpId`?
The `rpId` (Relying Party ID) is the **domain name** where your passkeys are registered (e.g., `app.example.com`).
- It **CANNOT** be an IP address or `localhost`.
- It **MUST** match the domain hosting your verification files.

### 1. iOS Configuration (Apple App Site Association)
To support Passkeys on iOS, you must host a file at `https://<rpId>/.well-known/apple-app-site-association`.

**Content:**
```json
{
  "webcredentials": {
    "apps": [
      "TEAMID.com.yourcompany.yourapp"
    ]
  }
}
```
*   Replace `TEAMID` with your Apple Team ID (simulated/real).
*   Replace `com.yourcompany.yourapp` with your Bundle ID.

**Xcode / Expo Config:**
Add the **Associated Domains** capability with: `webcredentials:<rpId>`

For Expo (`app.json`):
```json
"ios": {
  "associatedDomains": ["webcredentials:app.example.com"],
  "bundleIdentifier": "com.yourcompany.yourapp"
}
```

### 2. Android Configuration (AssetLinks)
To support Passkeys on Android, host a file at `https://<rpId>/.well-known/assetlinks.json`.

**Content:**
```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.yourcompany.yourapp",
      "sha256_cert_fingerprints": [
        "FA:C6:17:45:..."
      ]
    }
  }
]
```
*   `package_name`: Your Android application ID.
*   `sha256_cert_fingerprints`: The SHA-256 fingerprint of your signing certificate (Keystore).

**Expo Config:**
Ensure your package name matches:
```json
"android": {
  "package": "com.yourcompany.yourapp"
}
```

---

## Message Signing

Sign messages with the user's wallet for authentication or proof of ownership.

### Basic Message Signing

```tsx
import { useCavosNative } from '@cavos/react-native';

function SignMessage() {
  const { signMessage } = useCavosNative();

  const handleSign = async () => {
    // Signature relies on the underlying Starknet account
    const signature = await signMessage('Hello, Starknet!');
    
    console.log('r:', signature.r);
    console.log('s:', signature.s);
  };
}
```

**Signature Format:**
The signature is returned in Starknet's native format:
```typescript
interface Signature {
  r: bigint;
  s: bigint;
}
```

## Advanced Configuration

### Custom RPC Endpoints
Use your own RPC endpoint for better performance or privacy:

```tsx
<CavosNativeProvider
  config={{
    appId: 'your-app-id',
    rpId: 'app.domain.com',
    network: 'mainnet',
    starknetRpcUrl: 'https://your-custom-rpc.com/v0_8',
  }}
>
  <App />
</CavosNativeProvider>
```

### Custom Paymaster
Use your own paymaster for gasless transactions:

```tsx
<CavosNativeProvider
  config={{
    appId: 'your-app-id',
    rpId: 'app.domain.com',
    paymasterApiKey: 'your-avnu-api-key',
  }}
>
  <App />
</CavosNativeProvider>
```
> Note: You need an AVNU paymaster API key. Get one at avnu.fi

## Session Management

### Understanding Session State
The SDK manages session state automatically using `expo-secure-store`.

```tsx
const { isAuthenticated, address, requiresWalletCreation } = useCavosNative();

if (requiresWalletCreation) {
    // User is logged in (OAuth) but hasn't created/unlocked wallet yet
}
```

### Security
The private key is encrypted and stored locally. It requires biometric authentication (Passkey) to be decrypted into memory. 

### Manual Session Clearing
Sessions are cleared automatically on logout, but you can also clear manually:
```tsx
const { logout } = useCavosNative();
await logout();
```

## Direct SDK Access
Access the underlying SDK instance for advanced operations if needed (though hooking is preferred):

```tsx
const { cavos } = useCavosNative();
// access raw methods: cavos.getActiveAccount(), etc.
```

## Error Handling

### Common Error Types
1.  **Authentication Errors**: User cancelled the browser flow.
2.  **Passkey Errors**:
    *   `NotAllowedError`: User cancelled system prompt.
    *   `NotSupportedError`: Device doesn't support biometrics.
3.  **Transaction Errors**:
    *   Insufficient credits (Paymaster).
    *   Execution reverted (Contract logic).

## Troubleshooting

### Passkey Prompt Not Showing
*   **Simulator**: Passkeys often require a physical device or specific simulator configuration (Enrolled biometric).
*   **RPID Mismatch**: Ensure `rpId` in config matches your associated domain content.
*   **Permissions**: Ensure FaceID/TouchID usage description is in `Info.plist` (iOS).

### Transactions Failing
*   Check if `gasless: true` is passed and Paymaster has funds.
*   Verify contract address and calldata.
