import { createMcpHandler } from "mcp-handler";
import { z } from "zod";

const localCommandResult = (command: string[], tool: string) => ({
  content: [{
    type: "text" as const,
    text: JSON.stringify({
      tool,
      command,
      commandLine: command.map((part) => JSON.stringify(part)).join(" "),
      execution: "local-required",
      message: `${tool} is a native CLI and cannot run in Vercel serverless. Run this command locally only against systems you are authorized to test.`,
    }, null, 2),
  }],
});

const handler = createMcpHandler(
  async (server) => {
    server.tool(
      "scan_subdomains",
      "Scan target domain(s) for subdomains using subfinder. Returns a command to run locally because native scanning CLIs cannot execute on Vercel serverless.",
      {
        target: z.string().describe("Domain or file containing domains to scan"),
        domain_file: z.boolean().describe("Whether target is a file containing domains"),
        threads: z.number().int().positive().default(4).describe("Number of concurrent threads"),
      },
      async ({ target, domain_file, threads }) => localCommandResult(
        ["subfinder", domain_file ? "-list" : "-domain", target, "-json", "-all", "-silent", "-active", "-t", String(threads)],
        "subfinder",
      ),
    );

    server.tool(
      "scan_ports",
      "Scan a target for open ports using naabu. Returns a command to run locally because native scanning CLIs cannot execute on Vercel serverless.",
      {
        target: z.string().describe("Domain, IP, or file to scan"),
        file: z.boolean().describe("Whether target is a file containing targets"),
        ports: z.string().default("80,443").describe("Port range, comma-separated ports, or number of top ports"),
        top_ports: z.boolean().default(false).describe("Use ports as the number of top ports"),
        threads: z.number().int().positive().default(20).describe("Number of concurrent threads"),
      },
      async ({ target, file, ports, top_ports, threads }) => localCommandResult(
        ["naabu", "-silent", "-nc", "-c", String(threads), "-r", "8.8.8.8", "-skip-host-discovery", "-scan-all-ips", "-json", file ? "-list" : "-host", target, top_ports ? "-top-ports" : "-port", ports],
        "naabu",
      ),
    );

    server.tool(
      "analyze_http_services",
      "Analyze HTTP/HTTPS services using httpx. Returns a command to run locally because native scanning CLIs cannot execute on Vercel serverless.",
      {
        target: z.string().describe("Domain or file containing targets"),
        file: z.boolean().describe("Whether target is a file containing targets"),
        threads: z.number().int().positive().default(20).describe("Number of concurrent threads"),
      },
      async ({ target, file, threads }) => localCommandResult(
        ["httpx", "-silent", "-nc", "-threads", String(threads), "-json", "-title", "-status-code", "-content-length", "-server", "-tech-detect", file ? "-list" : "-target", target],
        "httpx",
      ),
    );

    server.tool(
      "detect_cdn",
      "Check whether a target domain uses a CDN with cdncheck. Returns a command to run locally because native scanning CLIs cannot execute on Vercel serverless.",
      {
        target: z.string().describe("Domain to check for CDN usage"),
        resolver: z.string().default("8.8.8.8").describe("DNS resolver to use"),
      },
      async ({ target, resolver }) => localCommandResult(
        ["cdncheck", "-input", target, "-resolver", resolver, "-nc", "-duc", "-silent", "-resp", "-jsonl"],
        "cdncheck",
      ),
    );

    server.tool(
      "analyze_tls_config",
      "Analyze TLS/SSL configuration using tlsx. Returns a command to run locally because native scanning CLIs cannot execute on Vercel serverless.",
      {
        target: z.string().describe("Domain or file containing targets"),
        file: z.boolean().describe("Whether target is a file containing targets"),
        port: z.number().int().positive().default(443).describe("TLS port to scan"),
        resolver: z.string().default("8.8.8.8").describe("DNS resolver to use"),
        threads: z.number().int().positive().default(300).describe("Number of concurrent threads"),
      },
      async ({ target, file, port, resolver, threads }) => localCommandResult(
        ["tlsx", "-silent", "-resolvers", resolver, "-nc", "-c", String(threads), "-p", String(port), "-json", "-so", "-tls-version", "-cipher", "-wildcard-cert", "-probe-status", "-version-enum", "-cipher-enum", "-cipher-type", "all", "-serial", file ? "-l" : "-u", target],
        "tlsx",
      ),
    );

    server.tool(
      "enumerate_assets",
      "Perform unified asset enumeration using gobuster modes dir, dns, vhost, fuzz, gcs, s3, or tftp. Returns a local command.",
      {
        mode: z.string().describe("Gobuster mode: dir, dns, vhost, fuzz, gcs, s3, or tftp"),
        target: z.string().optional().describe("Target URL, domain, or server"),
        wordlist: z.string().describe("Path to a local wordlist"),
        threads: z.number().int().positive().default(10),
        extensions: z.string().optional(),
        status_codes: z.string().optional(),
        output: z.string().optional(),
        resolver: z.string().optional(),
        append_domain: z.boolean().default(true),
        methods: z.string().optional(),
        project: z.string().optional(),
        region: z.string().optional(),
        server: z.string().optional(),
      },
      async ({ mode, target, wordlist, threads, extensions, status_codes, output, resolver, append_domain, methods, project, region, server: tftpServer }) => {
        const validModes = ["dir", "dns", "vhost", "fuzz", "gcs", "s3", "tftp"];
        if (!validModes.includes(mode)) throw new Error(`Unsupported gobuster mode: ${mode}`);
        if (["dir", "dns", "vhost", "fuzz"].includes(mode) && !target) throw new Error(`target is required for ${mode} mode`);
        if (mode === "tftp" && !tftpServer) throw new Error("server is required for tftp mode");
        const command = ["gobuster", mode, "-t", String(threads), "-q"];
        if (mode === "dir") {
          command.push("-u", `${target}/FUZZ`, "-w", wordlist);
          if (extensions) command.push("-x", extensions);
          if (status_codes) command.push("-s", status_codes);
        } else if (mode === "dns") {
          command.push("-d", target!, "-w", wordlist);
          if (resolver) command.push("-r", resolver);
        } else if (mode === "vhost") {
          command.push("-u", target!, "-w", wordlist);
          if (!append_domain) command.push("--append-domain=false");
        } else if (mode === "fuzz") {
          command.push("-u", target!, "-w", wordlist);
          if (methods) command.push("-m", methods);
        } else if (mode === "gcs") {
          command.push("-w", wordlist);
          if (project) command.push("--project", project);
        } else if (mode === "s3") {
          command.push("-w", wordlist);
          if (region) command.push("--region", region);
        } else {
          command.push("-w", wordlist, "--server", tftpServer!);
        }
        if (output) command.push("-o", output);
        return localCommandResult(command, "gobuster");
      },
    );

    server.tool(
      "fuzz_endpoints",
      "Fuzz a target for hidden endpoints using ffuf. Returns a command to run locally because native scanning CLIs cannot execute on Vercel serverless.",
      {
        target: z.string().describe("Target URL to fuzz"),
        threads: z.number().int().positive().default(40),
        wordlist: z.string().default("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/directory-list-2.3-medium.txt"),
      },
      async ({ target, threads, wordlist }) => localCommandResult(
        ["ffuf", "-s", "-w", wordlist, "-u", `${target}/FUZZ`, "-t", String(threads)],
        "ffuf",
      ),
    );

    server.tool(
      "resolve_dns",
      "Run DNS enumeration using dnsx. Returns a command to run locally because native scanning CLIs cannot execute on Vercel serverless.",
      {
        target: z.string().describe("Domain or file containing domains"),
        file: z.boolean().describe("Whether target is a file containing domains"),
        threads: z.number().int().positive().default(100),
        resolver: z.string().default("8.8.8.8"),
        wordlist: z.string().default("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"),
      },
      async ({ target, file, threads, resolver, wordlist }) => localCommandResult(
        ["dnsx", "-silent", "-t", String(threads), "-json", "-r", resolver, "-all", file ? "-l" : "-d", target, "-w", wordlist],
        "dnsx",
      ),
    );
  },
  {
    capabilities: {
      tools: {
        scan_subdomains: { description: "Scan target domains for subdomains using subfinder" },
        scan_ports: { description: "Scan targets for open ports using naabu" },
        analyze_http_services: { description: "Analyze HTTP and HTTPS services using httpx" },
        detect_cdn: { description: "Detect CDN usage using cdncheck" },
        analyze_tls_config: { description: "Analyze TLS and SSL configuration using tlsx" },
        enumerate_assets: { description: "Enumerate assets using gobuster" },
        fuzz_endpoints: { description: "Fuzz hidden web endpoints using ffuf" },
        resolve_dns: { description: "Enumerate and resolve DNS records using dnsx" },
      },
    },
  },
  { basePath: "", verboseLogs: true, maxDuration: 60, disableSse: true },
);

export { handler as GET, handler as POST, handler as DELETE };
