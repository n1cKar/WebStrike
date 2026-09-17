import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  transpilePackages: [
    "@webstrike/types",
    "@webstrike/validation",
    "@webstrike/security",
    "@webstrike/testing",
  ],
  serverExternalPackages: ["@neondatabase/serverless"],
  experimental: {
    optimizePackageImports: ["lucide-react", "motion"],
  },
};

export default nextConfig;