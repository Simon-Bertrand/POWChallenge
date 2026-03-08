import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: ['ioredis', 'argon2', 'powchallenge_server'],
  turbopack: {},
  webpack: (config, { isServer }) => {
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
      layers: true,
    };

    // Fix for argon2-browser WASM resolution issue in Next.js
    config.module.rules.push({
      test: /\.wasm$/,
      type: 'asset/resource',
    });

    if (isServer) {
      config.externals = [...(config.externals || []), 'argon2', 'powchallenge_server'];
    }

    return config;
  },
};

export default nextConfig;
