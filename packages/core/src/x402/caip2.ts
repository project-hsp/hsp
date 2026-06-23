/** CAIP-2 network ids for EVM: `eip155:<chainId>`. */

export function toCaip2(chainId: number): string {
  return `eip155:${chainId}`;
}

/** Parse an `eip155:<chainId>` network → numeric chainId. Throws on non-eip155 / malformed. */
export function parseCaip2(network: string): number {
  const m = /^eip155:(\d+)$/.exec(network.trim());
  if (!m) throw new Error(`unsupported CAIP-2 network (expected eip155:<chainId>): ${network}`);
  return Number(m[1]);
}

export function isEvmCaip2(network: string): boolean {
  return /^eip155:\d+$/.test(network.trim());
}
