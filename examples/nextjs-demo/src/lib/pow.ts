import { POWCaptchaServer } from 'powchallenge_server';

declare global {
    // eslint-disable-next-line no-var
    var powServer: POWCaptchaServer | undefined;
}

// Singleton pattern to ensure we only have one instance of the server
// This is important when using MemoryStorage
export const powServer = globalThis.powServer ?? new POWCaptchaServer(5, 300, false);

if (process.env.NODE_ENV !== 'production') globalThis.powServer = powServer;
