/** @type {import('next').NextConfig} */
export default {
  poweredByHeader: false,
  reactStrictMode: true,
  // Server Actions check that the Origin matches the Host; only these hosts are ours.
  experimental: { serverActions: { allowedOrigins: ['127.0.0.1:7800', 'localhost:7800'] } },
};
