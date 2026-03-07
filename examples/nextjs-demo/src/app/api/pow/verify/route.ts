import { NextResponse } from 'next/server';
import { powServer } from '@/lib/pow';

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const ip = request.headers.get('x-forwarded-for') || '127.0.0.1';

        const isValid = await powServer.verify_pow(body, ip);

        if (isValid) {
            return NextResponse.json({ message: 'Access Granted' });
        } else {
            return NextResponse.json({ error: 'Invalid Proof of Work' }, { status: 400 });
        }
    } catch (error: any) {
        return NextResponse.json({ error: error.message || 'Verification failed' }, { status: 400 });
    }
}
