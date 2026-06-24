/**
 * stdio entrypoint:  npx tsx packages/mcp/src/index.ts
 * (see .mcp.json.example at the repo root for client registration)
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { depsFromEnv } from './config.js';
import { buildServer } from './server.js';

const deps = depsFromEnv();
const server = buildServer(deps);
await server.connect(new StdioServerTransport());
console.error(
  `[hsp-mcp] ready (pure / key-less) · chain ${deps.chain.name} (${deps.chain.chainId})` +
    (deps.pinnedAdapterAddress ? ` · pinned adapter ${deps.pinnedAdapterAddress}` : ' · no pinned adapter (pass adapterAddress per call)'),
);
