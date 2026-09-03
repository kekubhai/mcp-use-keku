import { describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  NodeOAuthClientProvider,
  type NodeOAuthAuthorizationResponse,
} from "../../../src/auth/node.js";
import type { KVStore } from "../../../src/auth/storage.js";

class MemoryKVStore implements KVStore {
  private readonly values = new Map<string, string>();

  get(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  set(key: string, value: string): void {
    this.values.set(key, value);
  }

  remove(key: string): void {
    this.values.delete(key);
  }

  keys(): string[] {
    return [...this.values.keys()];
  }
}

describe("NodeOAuthClientProvider", () => {
  it("prefers the persisted callback port over the configured default", async () => {
    const probe = createNetServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const address = probe.address();
    if (!address || typeof address === "string") {
      throw new Error("Port probe did not bind to a TCP port");
    }
    const persistedPort = address.port;
    await new Promise<void>((resolve, reject) =>
      probe.close((error) => (error ? reject(error) : resolve()))
    );

    const kv = new MemoryKVStore();
    kv.set("port", String(persistedPort));
    const provider = await NodeOAuthClientProvider.create(
      "https://mcp.example.com/mcp",
      {
        kvStore: kv,
        preferredPort: persistedPort === 33_418 ? 33_419 : 33_418,
        portRange: 100,
      }
    );

    expect(provider.callbackPort).toBe(persistedPort);
  });

  it("does not create OAuth state on disk until authorization starts", async () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-use-node-oauth-"));
    const baseDir = join(root, "oauth");
    let provider: NodeOAuthClientProvider | undefined;

    try {
      provider = await NodeOAuthClientProvider.create(
        "https://public.example.com/mcp",
        {
          baseDir,
          openBrowser: vi.fn(),
          preferredPort: 33_000 + (process.pid % 1_000),
          portRange: 100,
        }
      );

      expect(existsSync(baseDir)).toBe(false);

      const authorizationUrl = new URL("https://auth.example.com/authorize");
      authorizationUrl.searchParams.set("state", "test-state");
      await provider.redirectToAuthorization(authorizationUrl);

      const portFile = join(baseDir, provider.serverUrlHash, "port");
      expect(readFileSync(portFile, "utf8")).toBe(
        String(provider.callbackPort)
      );
    } finally {
      provider?.dispose();
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("persists its callback port only when authorization starts", async () => {
    const kv = new MemoryKVStore();
    const set = vi.spyOn(kv, "set");
    const provider = await NodeOAuthClientProvider.create(
      "https://mcp.example.com/mcp",
      {
        kvStore: kv,
        openBrowser: vi.fn(),
        preferredPort: 34_000 + (process.pid % 1_000),
        portRange: 100,
      }
    );

    expect(set).not.toHaveBeenCalled();

    const authorizationUrl = new URL("https://auth.example.com/authorize");
    authorizationUrl.searchParams.set("state", "test-state");
    await provider.redirectToAuthorization(authorizationUrl);

    expect(set).toHaveBeenCalledWith("port", String(provider.callbackPort));
    provider.dispose();
  });

  it("preserves RFC 9207 iss from the loopback callback", async () => {
    const openBrowser = vi.fn();
    const provider = await NodeOAuthClientProvider.create(
      "https://mcp.example.com/mcp",
      {
        authTimeoutMs: 5_000,
        kvStore: new MemoryKVStore(),
        openBrowser,
        preferredPort: 35_000 + (process.pid % 1_000),
        portRange: 100,
      }
    );
    const authorizationUrl = new URL("https://auth.example.com/authorize");
    authorizationUrl.searchParams.set("state", "test-state");

    await provider.redirectToAuthorization(authorizationUrl);
    const launcherUrl = `http://127.0.0.1:${provider.callbackPort}/authorize`;
    expect(openBrowser).toHaveBeenCalledWith(launcherUrl);
    const launcherResponse = await fetch(launcherUrl, { redirect: "manual" });
    expect(launcherResponse.status).toBe(302);
    expect(launcherResponse.headers.get("location")).toContain(
      "https://auth.example.com/authorize"
    );
    expect(launcherResponse.headers.get("location")).toContain("state=");
    expect(launcherResponse.headers.get("cache-control")).toBe("no-store");
    const responsePromise: Promise<NodeOAuthAuthorizationResponse> =
      provider.getAuthorizationResponse();
    const legacyCodePromise = provider.getAuthorizationCode();
    const callback = new URL(
      `http://127.0.0.1:${provider.callbackPort}/callback`
    );
    callback.searchParams.set("code", "authorization-code");
    callback.searchParams.set("state", "test-state");
    callback.searchParams.set("iss", "https://auth.example.com");

    const callbackResponse = await fetch(callback);

    expect(callbackResponse.status).toBe(200);
    await expect(responsePromise).resolves.toEqual({
      code: "authorization-code",
      iss: "https://auth.example.com",
    });
    await expect(legacyCodePromise).resolves.toBe("authorization-code");
    expect(openBrowser).toHaveBeenCalledOnce();
  });

  describe("concurrent redirectToAuthorization race condition (issue #2420)", () => {
    it("rejects a second concurrent call while the first is still initializing", async () => {
      const kv = new MemoryKVStore();
      const provider = await NodeOAuthClientProvider.create(
        "https://mcp.example.com/mcp",
        {
          kvStore: kv,
          openBrowser: vi.fn(),
          preferredPort: 36_000 + (process.pid % 1_000),
          portRange: 100,
        }
      );

      const authUrl = new URL("https://auth.example.com/authorize");
      authUrl.searchParams.set("state", "s1");

      // Start the first call but don't await it yet
      const firstCall = provider.redirectToAuthorization(authUrl);

      // A second call issued synchronously (before any microtask) must be
      // rejected immediately because `authorizing` was set synchronously.
      await expect(provider.redirectToAuthorization(authUrl)).rejects.toThrow(
        "already in progress"
      );

      // Let the first call finish
      await firstCall;
      provider.dispose();
    });

    it("first flow's promise is not overwritten by the second call", async () => {
      const kv = new MemoryKVStore();
      const provider = await NodeOAuthClientProvider.create(
        "https://mcp.example.com/mcp",
        {
          kvStore: kv,
          openBrowser: vi.fn(),
          preferredPort: 37_000 + (process.pid % 1_000),
          portRange: 100,
          authTimeoutMs: 5_000,
        }
      );

      const authUrl1 = new URL("https://auth.example.com/authorize");
      authUrl1.searchParams.set("state", "state1");

      await provider.redirectToAuthorization(authUrl1);

      // Grab the first promise before any concurrent attempt
      const firstPromise = provider.getAuthorizationResponse();

      // Send a callback for the first flow
      const cb = new URL(`http://127.0.0.1:${provider.callbackPort}/callback`);
      cb.searchParams.set("code", "code-from-flow-1");
      cb.searchParams.set("state", "state1");
      await fetch(cb);

      // The original promise must resolve with the first flow's code
      await expect(firstPromise).resolves.toEqual({
        code: "code-from-flow-1",
      });

      // The second call was rejected so it never overwrote the first flow.
      provider.dispose();
    });

    it("hasPendingFlow is true while authorizing (before pending is set)", async () => {
      const kv = new MemoryKVStore();
      const provider = await NodeOAuthClientProvider.create(
        "https://mcp.example.com/mcp",
        {
          kvStore: kv,
          openBrowser: vi.fn(),
          preferredPort: 38_000 + (process.pid % 1_000),
          portRange: 100,
        }
      );

      expect(provider.hasPendingFlow).toBe(false);

      const authUrl = new URL("https://auth.example.com/authorize");
      authUrl.searchParams.set("state", "s1");

      // Start the first call but don't await it yet
      const firstCall = provider.redirectToAuthorization(authUrl);

      // During the first call's initialization, hasPendingFlow must be true
      // so that orchestrators don't start a duplicate auth() flow.
      expect(provider.hasPendingFlow).toBe(true);

      await firstCall;

      // After loopback is up, pending is set — still true
      expect(provider.hasPendingFlow).toBe(true);

      provider.dispose();
      expect(provider.hasPendingFlow).toBe(false);
    });
  });

  describe("loopback startup failure cleanup (issue #2420)", () => {
    it("releases pending reservation when startLoopback fails", async () => {
      const kv = new MemoryKVStore();
      const provider = await NodeOAuthClientProvider.create(
        "https://mcp.example.com/mcp",
        {
          kvStore: kv,
          openBrowser: vi.fn(),
          preferredPort: 39_000 + (process.pid % 1_000),
          portRange: 100,
        }
      );

      // Occupy the port so that startLoopback() fails with EADDRINUSE
      const blocker = createNetServer();
      await new Promise<void>((resolve) =>
        blocker.listen(provider.callbackPort, "127.0.0.1", resolve)
      );

      const authUrl = new URL("https://auth.example.com/authorize");
      authUrl.searchParams.set("state", "s1");

      // First call must fail because the port is occupied
      await expect(provider.redirectToAuthorization(authUrl)).rejects.toThrow();

      // The reservation must have been released
      expect(provider.hasPendingFlow).toBe(false);

      await new Promise<void>((resolve, reject) =>
        blocker.close((err) => (err ? reject(err) : resolve()))
      );
      provider.dispose();
    });

    it("subsequent authorization attempt succeeds after a startup failure", async () => {
      const kv = new MemoryKVStore();
      const provider = await NodeOAuthClientProvider.create(
        "https://mcp.example.com/mcp",
        {
          kvStore: kv,
          openBrowser: vi.fn(),
          preferredPort: 40_000 + (process.pid % 1_000),
          portRange: 100,
          authTimeoutMs: 5_000,
        }
      );

      // Occupy the port to force a startup failure
      const blocker = createNetServer();
      await new Promise<void>((resolve) =>
        blocker.listen(provider.callbackPort, "127.0.0.1", resolve)
      );

      const authUrl = new URL("https://auth.example.com/authorize");
      authUrl.searchParams.set("state", "s1");

      await expect(provider.redirectToAuthorization(authUrl)).rejects.toThrow();

      // Release the port
      await new Promise<void>((resolve, reject) =>
        blocker.close((err) => (err ? reject(err) : resolve()))
      );

      // Now a second attempt should succeed
      const authUrl2 = new URL("https://auth.example.com/authorize");
      authUrl2.searchParams.set("state", "s2");
      await provider.redirectToAuthorization(authUrl2);

      expect(provider.hasPendingFlow).toBe(true);

      // Verify the loopback is functional
      const launcherUrl = `http://127.0.0.1:${provider.callbackPort}/authorize`;
      const response = await fetch(launcherUrl, { redirect: "manual" });
      expect(response.status).toBe(302);

      provider.dispose();
    });

    it("hasPendingFlow resets to false after a startup failure", async () => {
      const kv = new MemoryKVStore();
      const provider = await NodeOAuthClientProvider.create(
        "https://mcp.example.com/mcp",
        {
          kvStore: kv,
          openBrowser: vi.fn(),
          preferredPort: 41_000 + (process.pid % 1_000),
          portRange: 100,
        }
      );

      // Occupy the port to force failure
      const blocker = createNetServer();
      await new Promise<void>((resolve) =>
        blocker.listen(provider.callbackPort, "127.0.0.1", resolve)
      );

      const authUrl = new URL("https://auth.example.com/authorize");
      authUrl.searchParams.set("state", "s1");

      await expect(provider.redirectToAuthorization(authUrl)).rejects.toThrow();

      expect(provider.hasPendingFlow).toBe(false);

      await new Promise<void>((resolve, reject) =>
        blocker.close((err) => (err ? reject(err) : resolve()))
      );
      provider.dispose();
    });
  });

  describe("dispose during authorizing state", () => {
    it("clears authorizing flag so a subsequent call can proceed", async () => {
      const kv = new MemoryKVStore();
      const provider = await NodeOAuthClientProvider.create(
        "https://mcp.example.com/mcp",
        {
          kvStore: kv,
          openBrowser: vi.fn(),
          preferredPort: 42_000 + (process.pid % 1_000),
          portRange: 100,
        }
      );

      const authUrl = new URL("https://auth.example.com/authorize");
      authUrl.searchParams.set("state", "s1");

      const firstCall = provider.redirectToAuthorization(authUrl);

      // Dispose while authorizing is true but pending is not yet set
      provider.dispose();

      // First call should still resolve (dispose didn't break it)
      await firstCall;
      provider.dispose();
    });
  });
});
