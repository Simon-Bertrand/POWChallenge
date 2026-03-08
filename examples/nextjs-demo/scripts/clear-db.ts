import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
    console.log('--- Cleaning PoW Database Tables ---');

    try {
        const subnet = await prisma.powSubnetHistory.deleteMany({});
        console.log(`- Deleted ${subnet.count} subnet history entries`);

        const global = await prisma.powGlobalSolve.deleteMany({});
        console.log(`- Deleted ${global.count} global solve entries`);

        const activity = await prisma.powIpActivity.deleteMany({});
        console.log(`- Deleted ${activity.count} IP activity entries`);

        const fingerprint = await prisma.powFingerprintHistory.deleteMany({});
        console.log(`- Deleted ${fingerprint.count} fingerprint history entries`);

        const challenges = await prisma.powChallenge.deleteMany({});
        console.log(`- Deleted ${challenges.count} active challenges`);

        console.log('--- Cleanup Complete ---');
    } catch (error) {
        console.error('Error cleaning database:', error);
    } finally {
        await prisma.$disconnect();
    }
}

main();
