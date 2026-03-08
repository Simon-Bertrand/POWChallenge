import { PrismaClient } from '@prisma/client';
import { StorageBackend, ChallengeState } from './storage';

const prisma = new PrismaClient();

export class PrismaStorage implements StorageBackend {
    private prisma: PrismaClient;
    public max_challenges: number;

    constructor(max_challenges: number = 10000) {
        this.prisma = prisma;
        this.max_challenges = max_challenges;
    }

    // ── Challenge Management ──────────────────────────────────────────────

    async store_challenge(
        req_id: string,
        challenge_bytes: Buffer,
        ip: string,
        difficulty: number,
        timestamp: Date,
        validity_seconds: number
    ): Promise<void> {
        // Passive Cleanup: Remove challenges older than their specific validity
        const challengeCutoff = new Date(Date.now() - validity_seconds * 1000);

        // Also clean IP activity older than 1 hour to prevent table bloat
        const ipActivityCutoff = new Date(Date.now() - 3600 * 1000);

        await this.prisma.$transaction([
            this.prisma.powChallenge.deleteMany({ where: { timestamp: { lt: challengeCutoff } } }),
            this.prisma.powIpActivity.deleteMany({ where: { timestamp: { lt: ipActivityCutoff } } })
        ]);

        // Capacity Check
        const count = await this.prisma.powChallenge.count();
        if (count >= this.max_challenges) {
            throw new Error('Server busy');
        }

        // Atomic storage of challenge and IP lock
        await this.prisma.$transaction([
            this.prisma.powChallenge.create({
                data: { req_id, challenge: challenge_bytes, ip, difficulty, timestamp }
            }),
            this.prisma.powIpActivity.upsert({
                where: { ip },
                update: { timestamp },
                create: { ip, timestamp },
            })
        ]);
    }

    async fetch_challenge(req_id: string): Promise<ChallengeState | null> {
        const challenge = await this.prisma.powChallenge.findUnique({
            where: { req_id }
        });

        if (!challenge) return null;

        // Optional: Add a check here to match the validity logic in index.ts
        // if ((Date.now() - challenge.timestamp.getTime()) / 1000 > 300) return null;

        return {
            challenge: Buffer.from(challenge.challenge),
            ip: challenge.ip,
            timestamp: challenge.timestamp,
            difficulty: challenge.difficulty
        };
    }

    async delete_challenge(req_id: string): Promise<boolean> {
        const challenge = await this.prisma.powChallenge.findUnique({
            where: { req_id },
            select: { ip: true }
        });

        if (challenge) {
            try {
                await this.prisma.$transaction([
                    this.prisma.powChallenge.delete({ where: { req_id } }),
                    this.prisma.powIpActivity.deleteMany({ where: { ip: challenge.ip } })
                ]);
                return true;
            } catch {
                return false;
            }
        }
        return false;
    }

    async count_challenges(): Promise<number> {
        return this.prisma.powChallenge.count();
    }

    async is_ip_active(ip: string): Promise<boolean> {
        const ipRecord = await this.prisma.powIpActivity.findUnique({ where: { ip } });
        return ipRecord !== null;
    }

    // ── Scaling Difficulty History (Self-Cleaning) ────────────────────────

    async increment_subnet_history(subnet: string): Promise<void> {
        const cutoff = new Date(Date.now() - 60 * 1000); // 1-minute window 

        // Prune stale subnet entries to keep difficulty scaling accurate
        await this.prisma.powSubnetHistory.deleteMany({
            where: { updatedAt: { lt: cutoff } }
        });

        await this.prisma.powSubnetHistory.upsert({
            where: { subnet },
            update: { count: { increment: 1 } },
            create: { subnet, count: 1 }
        });
    }

    async get_subnet_history(subnet: string): Promise<number> {
        const cutoff = new Date(Date.now() - 60 * 1000);

        const record = await this.prisma.powSubnetHistory.findUnique({ where: { subnet } });

        // If the record exists but is older than 60s, it shouldn't count for scaling
        if (record && record.updatedAt >= cutoff) {
            return record.count;
        }
        return 0;
    }

    async increment_fingerprint_history(fingerprint: string): Promise<void> {
        const cutoff = new Date(Date.now() - 60 * 1000);

        await this.prisma.powFingerprintHistory.deleteMany({
            where: { updatedAt: { lt: cutoff } }
        });

        await this.prisma.powFingerprintHistory.upsert({
            where: { fingerprint },
            update: { count: { increment: 1 } },
            create: { fingerprint, count: 1 }
        });
    }

    async get_fingerprint_history(fingerprint: string): Promise<number> {
        const cutoff = new Date(Date.now() - 60 * 1000);
        const record = await this.prisma.powFingerprintHistory.findUnique({ where: { fingerprint } });

        if (record && record.updatedAt >= cutoff) {
            return record.count;
        }
        return 0;
    }

    // ── Global Solve History ─────────────────────────────────────────────

    async add_global_solve(timestamp: Date): Promise<void> {
        // Global solves are checked against a 300s (5min) window in index.ts 
        const cutoff = new Date(Date.now() - 300 * 1000);

        await this.prisma.$transaction([
            // Clean global history on every solve to prevent infinite growth
            this.prisma.powGlobalSolve.deleteMany({ where: { timestamp: { lt: cutoff } } }),
            this.prisma.powGlobalSolve.create({ data: { timestamp } })
        ]);
    }

    async get_recent_global_solves_count(window_seconds: number): Promise<number> {
        const cutoff = new Date(Date.now() - window_seconds * 1000);
        return this.prisma.powGlobalSolve.count({
            where: { timestamp: { gte: cutoff } }
        });
    }
}