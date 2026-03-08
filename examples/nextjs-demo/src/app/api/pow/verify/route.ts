import { NextRequest, NextResponse } from 'next/server';
import { powServer } from '@/lib/pow';
import { InvalidProofOfWork, ChallengeNotFoundOrExpired, DifficultyMismatch } from 'powchallenge_server';

export async function POST(req: NextRequest) {
    try {
        const body = await req.json();
        const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';

        await powServer.verify_pow(body, ip);

        return NextResponse.json({ success: true, message: "Proof of Work validated successfully." });
    } catch (e: any) {
        if (
            e instanceof InvalidProofOfWork ||
            e instanceof ChallengeNotFoundOrExpired ||
            e instanceof DifficultyMismatch
        ) {
            return NextResponse.json({ error: e.message }, { status: 400 });
        }
        return NextResponse.json({ error: e.message || 'Internal Server Error' }, { status: 500 });
    }
}
