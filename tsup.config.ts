import { defineConfig } from 'tsup';

export default defineConfig({
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: true,
    external: [
        'react',
        'react-native',
        'react-native-passkey',
        'react-native-quick-crypto',
        '@react-native-async-storage/async-storage',
    ],
    treeshake: true,
    minify: false,
});
