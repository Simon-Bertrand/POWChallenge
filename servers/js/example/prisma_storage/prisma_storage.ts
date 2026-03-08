import { PrismaClient } from '@prisma/client';
import { StorageBackend, ChallengeState } from 'powchallenge_server';

export class PrismaStorage implements StorageBackend {
    private prisma: PrismaClient;
    public max_challenges: number;

    constructor(max_challenges: number = 10000) {
        this.prisma = new PrismaClient();
        this.max_challenges = max_challenges;
    }

    async store_challenge(
        req_id: string,
        challenge_bytes: Buffer,
        ip: string,
        difficulty: number,
        timestamp: Date,
        validity_seconds: number
    ): Promise<void> {
        // Run a cleanup of expired challenges before counting
        const cutoff = new Date(Date.now() - validity_seconds * 1000);
        await this.prisma.powChallenge.deleteMany({
            where: { timestamp: { lt: cutoff } }
        });

        // Count challenges and reject if we reached the maximum
        const count = await this.prisma.powChallenge.count();
        if (count >= this.max_challenges) {
            throw new Error('Server busy');
        }

        // Use Prisma transaction to store both challenge and IP activity
        await this.prisma.$transaction([
            this.prisma.powChallenge.create({
                data: {
                    req_id,
                    challenge: challenge_bytes,
                    ip,
                    difficulty,
                    timestamp,
                }
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

        if (!challenge) {
            return null;
        }

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
                // Delete both challenge and associated active IP flag
                await this.prisma.$transaction([
                    this.prisma.powChallenge.delete({ where: { req_id } }),
                    this.prisma.powIpActivity.deleteMany({ where: { ip: challenge.ip } })
                ]);
                return true;
            } catch (e) {
                return false; // Already deleted by a concurrent request
            }
        }
        return false;
    }

    async count_challenges(): Promise<number> {
        return this.prisma.powChallenge.count();
    }

    async is_ip_active(ip: string): Promise<boolean> {
        const ipRecord = await this.prisma.powIpActivity.findUnique({
            where: { ip }
        });
        return ipRecord !== null;
    }

    async increment_subnet_history(subnet: string): Promise<void> {
        await this.prisma.powSubnetHistory.upsert({
            where: { subnet },
            update: { count: { increment: 1 } },
            create: { subnet, count: 1 }
        });
    }

    async get_subnet_history(subnet: string): Promise<number> {
        const record = await this.prisma.powSubnetHistory.findUnique({
            where: { subnet }
        });
        return record?.count ?? 0;
    }

    async increment_fingerprint_history(fingerprint: string): Promise<void> {
        await this.prisma.powFingerprintHistory.upsert({
            where: { fingerprint },
            update: { count: { increment: 1 } },
            create: { fingerprint, count: 1 }
        });
    }

    async get_fingerprint_history(fingerprint: string): Promise<number> {
        const record = await this.prisma.powFingerprintHistory.findUnique({
            where: { fingerprint }
        });
        return record?.count ?? 0;
    }

    async add_global_solve(timestamp: Date): Promise<void> {
        await this.prisma.powGlobalSolve.create({
            data: { timestamp }
        });

        // Evict older global solves (older than 2 minutes for instance)
        const cutoff = new Date(Date.now() - 120 * 1000);
        await this.prisma.powGlobalSolve.deleteMany({
            where: { timestamp: { lt: cutoff } }
        });
    }

    async get_recent_global_solves_count(window_seconds: number): Promise<number> {
        const cutoff = new Date(Date.now() - window_seconds * 1000);
        return this.prisma.powGlobalSolve.count({
            where: { timestamp: { gte: cutoff } }
        });
    }
}
