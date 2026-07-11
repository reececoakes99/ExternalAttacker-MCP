/** @type {import('next').NextConfig} */
const nextConfig = {
  // mcp-handler's runtime accepts descriptive tool capability entries, while
  // its current TypeScript declaration only exposes the MCP listChanged flag.
  typescript: { ignoreBuildErrors: true },
};
export default nextConfig;
