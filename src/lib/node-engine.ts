/** Internal host-Node guard; never bundled into generated edge runtimes. */
export function assertSupportedNode(directExecution = false): void {
  const [major, minor, patch] = process.versions.node.split('.').map(Number);
  if (major > 20 || (major === 20 && (minor > 17 || (minor === 17 && patch >= 0)))) return;
  const error = Object.assign(new Error(
    `ERR_CSF_UNSUPPORTED_NODE: Node.js >=20.17.0 is required; current ${process.versions.node}. Upgrade Node.js before using cdn-security-framework.`,
  ), { code: 'ERR_CSF_UNSUPPORTED_NODE', required: '>=20.17.0', current: process.versions.node });
  if (directExecution) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
  throw error;
}
