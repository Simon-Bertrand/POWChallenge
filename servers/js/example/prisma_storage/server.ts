import { POWCaptchaServer } from 'powchallenge_server';
import { PrismaStorage } from './prisma_storage';
import express, { Request, Response } from 'express';

const app = express();
app.use(express.json());

// Initialize the Prisma-backed storage
const prismaStorage = new PrismaStorage(10000);

// Pass it to the CAPTCHA server
const difficulty = 10;
const captchaServer = new POWCaptchaServer(difficulty, 300, false, null, 3600, prismaStorage);

app.get('/challenge', async (req: Request, res: Response) => {
    try {
        const result = await captchaServer.get_challenge(req.ip || "127.0.0.1");
        res.json(result);
    } catch (e: any) {
        res.status(400).json({ error: e.message });
    }
});

app.post('/verify', async (req: Request, res: Response) => {
    try {
        await captchaServer.verify_pow(req.body, req.ip || "127.0.0.1");
        res.json({ message: 'Proof of Work validated successfully via Prisma Storage.' });
    } catch (e: any) {
        res.status(400).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 8084;
app.listen(PORT, () => {
    console.log(`Prisma POW Captcha Example listening at http://localhost:${PORT}`);
});
