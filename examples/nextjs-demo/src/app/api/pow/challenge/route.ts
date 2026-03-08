import { NextRequest, NextResponse } from 'next/server';
import { powServer } from '@/lib/pow';
import { ChallengeAlreadyActive, ServerBusy } from 'powchallenge_server';

export async function GET(req: NextRequest) {
    try {
        const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';
        const challenge = await powServer.get_challenge(ip);
        return NextResponse.json(challenge);
    } catch (e: any) {
        if (e instanceof ChallengeAlreadyActive) {
            return NextResponse.json({ error: e.message }, { status: 429 });
        }
        if (e instanceof ServerBusy) {
            return NextResponse.json({ error: e.message }, { status: 503 });
        }
        return NextResponse.json({ error: e.message || 'Internal Server Error' }, { status: 400 });
    }
}
