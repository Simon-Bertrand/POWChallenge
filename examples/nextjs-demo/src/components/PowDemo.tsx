'use client';

import { useState } from 'react';
import { minePOWWithWorker } from 'powchallenge_client';

export default function PowDemo() {
    const [status, setStatus] = useState<'idle' | 'fetching' | 'mining' | 'verifying' | 'success' | 'error'>('idle');
    const [message, setMessage] = useState('');
    const [difficulty, setDifficulty] = useState<number | null>(null);

    // Helper to decode base64 string to Uint8Array
    const base64ToBytes = (base64: string): Uint8Array => {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    };

    // Helper to encode Uint8Array to base64 string
    const bytesToBase64 = (bytes: Uint8Array): string => {
        return btoa(String.fromCharCode(...Array.from(bytes)));
    };

    const startAction = async () => {
        try {
            setStatus('fetching');
            setMessage('Fetching challenge...');

            // 1. Fetch challenge
            const res = await fetch('/api/pow/challenge');
            const challengeData = await res.json();
            console.log("challenge", challengeData)
            if (!res.ok) throw new Error(challengeData.error || 'Failed to fetch challenge');

            setDifficulty(challengeData.difficulty);
            // 2. Mine PoW
            setStatus('mining');
            setMessage(`Mining PoW (Difficulty: ${challengeData.difficulty})...`);

            // 2. Mine the PoW in a background thread (non-blocking)
            const t0 = Date.now();
            const challengeBytes = base64ToBytes(challengeData.challenge);
            const validNonceBytes = await minePOWWithWorker(challengeBytes, challengeData.difficulty);
            console.log(`PoW Solved in ${Date.now() - t0}ms`);

            // 3. Submit proof
            const verifyRes = await fetch('/api/pow/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    req_id: challengeData.req_id,
                    challenge: challengeData.challenge,
                    nonce: bytesToBase64(validNonceBytes),
                    difficulty: challengeData.difficulty,
                    timestamp: new Date().toISOString()
                })
            });

            if (verifyRes.ok) {
                setStatus('success');
                setMessage('Access Granted! PoW verified successfully.');
            } else {
                const errorData = await verifyRes.json();
                throw new Error(errorData.error || 'Verification failed');
            }
        } catch (err: any) {
            console.error(err);
            setStatus('error');
            setMessage(err.message || 'An error occurred');
        }
    };

    return (
        <div className="p-8 max-w-md mx-auto bg-white rounded-xl shadow-md space-y-4 border border-gray-200 mt-10">
            <h1 className="text-2xl font-bold text-gray-800">POW_WebGL Demo</h1>
            <p className="text-gray-600">
                This demo shows the Argon2id Proof-of-Work system working in Next.js.
            </p>

            <div className="flex flex-col space-y-2">
                <button
                    onClick={startAction}
                    disabled={status !== 'idle' && status !== 'success' && status !== 'error'}
                    className={`px-4 py-2 rounded-lg font-semibold transition-colors ${status === 'idle' || status === 'success' || status === 'error'
                        ? 'bg-blue-600 text-white hover:bg-blue-700'
                        : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                        }`}
                >
                    {status === 'idle' ? 'Start Protected Action' : 'Restart Demo'}
                </button>

                {status !== 'idle' && (
                    <div className={`mt-4 p-4 rounded-lg border ${status === 'success' ? 'bg-green-50 border-green-200 text-green-700' :
                        status === 'error' ? 'bg-red-50 border-red-200 text-red-700' :
                            'bg-blue-50 border-blue-200 text-blue-700'
                        }`}>
                        <p className="font-medium flex items-center">
                            {status === 'mining' && (
                                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                            )}
                            {message}
                        </p>
                        {difficulty !== null && <p className="text-xs mt-1 opacity-75">Work difficulty: {difficulty} bits</p>}
                    </div>
                )}
            </div>
        </div>
    );
}
