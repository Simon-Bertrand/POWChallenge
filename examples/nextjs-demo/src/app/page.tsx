import PowDemo from '@/components/PowDemo';

export default function Home() {
  return (
    <main className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
      <PowDemo />
      <footer className="mt-12 text-gray-500 text-sm">
        Powered by POW_WebGL • Argon2id Memory-Hard PoW
      </footer>
    </main>
  );
}
