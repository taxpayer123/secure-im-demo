/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_E2EE_PSK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
