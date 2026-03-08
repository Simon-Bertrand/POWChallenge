import { POWCaptchaServer } from 'powchallenge_server';
import { PrismaStorage } from './PrismaStorage';

declare global {
    var powServer: POWCaptchaServer | undefined;
}

export const prismaStorage = new PrismaStorage(10000);

export const powServer = new POWCaptchaServer(
    5,
    300,
    false,
    0.5,
    3600,
    prismaStorage,
    true
);

if (process.env.NODE_ENV !== 'production') {
    globalThis.powServer = powServer;
}
