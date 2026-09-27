// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Before each request the plugin runs the hooks' listener-owner check through
// `node:child_process` on the platform it reads from `process`. Amp provides
// both at runtime. As with node-os.d.ts, declare only the members the plugin
// uses instead of pulling in @types/node, so a drift in how it uses them
// still fails the typecheck.
declare module 'node:child_process' {
  export function execFile(
    file: string,
    args: readonly string[],
    options: {
      env: Record<string, string>
      timeout: number
      maxBuffer: number
      windowsHide: boolean
    },
    callback: (error: Error | null, stdout: string, stderr: string) => void,
  ): unknown
}

declare const process: {
  readonly platform: string
}
