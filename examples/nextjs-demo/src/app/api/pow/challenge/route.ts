import { NextResponse } from 'next/server';
import { powServer } from '@/lib/pow';

export async function GET(request: Request) {
    try {
        const ip = request.headers.get('x-forwarded-for') || '127.0.0.1';
        const challenge = await powServer.get_challenge(ip);
        return NextResponse.json(challenge);
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}
