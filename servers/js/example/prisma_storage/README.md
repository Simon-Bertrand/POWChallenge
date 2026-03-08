# Prisma Storage Backend Example

This directory contains an example of how to implement a custom `StorageBackend` for `powchallenge_server` using [Prisma](https://www.prisma.io/).

Prisma allows you to connect to various databases (PostgreSQL, MySQL, SQLite, MongoDB, etc.) with a single abstraction layer. Here, we demonstrate how to persist Proof of Work CAPTCHA challenges to a database, ensuring atomicity and transactional safety.

## How to Run the Example

1. **Install dependencies**:
   ```bash
   bun install
   ```

2. **Generate the Prisma Client**:
   This example uses SQLite for simplicity. Initialize the database schema:
   ```bash
   bunx prisma generate
   bunx prisma db push
   ```

3. **Start the server**:
   ```bash
   bun start
   ```

4. **Test the endpoints**:
   - Get a challenge:
     ```bash
     curl -X GET http://localhost:8084/challenge
     ```
   - Verify a PoW solution (use the provided client script or your own PoW solver):
     ```bash
     curl -X POST http://localhost:8084/verify \
       -H "Content-Type: application/json" \
       -d '{"req_id": "...", "challenge": "...", "difficulty": 10, "nonce": "...", "timestamp": "..."}'
     ```

## Key Files

- `prisma/schema.prisma`: The database schema definition containing models for challenges, IPs, and historical metrics.
- `prisma_storage.ts`: The custom implementation of the `StorageBackend` interface utilizing Prisma.
- `server.ts`: The Express application that instantiates the `POWCaptchaServer` and overrides its default storage backend with the custom `PrismaStorage`.
