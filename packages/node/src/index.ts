/**
 * @sirr/sdk — Sirr (سر) Node.js client
 *
 * Thin fetch wrapper around the Sirr HTTP API.
 * No native dependencies. Works in Node 18+.
 */

export interface SirrClientOptions {
  /** Sirr server base URL. Default: http://localhost:8080 */
  server?: string;
  /** Bearer token (SIRR_MASTER_KEY on the server side). */
  token: string;
}

export interface PushOptions {
  /** TTL in seconds. */
  ttl?: number;
  /** Maximum number of reads before the secret self-destructs. */
  reads?: number;
}

export interface SecretMeta {
  key: string;
  created_at: number;
  expires_at: number | null;
  max_reads: number | null;
  read_count: number;
}

class SirrError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(`Sirr API error ${status}: ${message}`);
    this.name = "SirrError";
  }
}

export class SirrClient {
  private readonly server: string;
  private readonly token: string;

  constructor(opts: SirrClientOptions) {
    this.server = (opts.server ?? "http://localhost:8080").replace(/\/$/, "");
    this.token = opts.token;
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      "Content-Type": "application/json",
    };
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const res = await fetch(`${this.server}${path}`, {
      method,
      headers: this.headers(),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    const json = (await res.json()) as Record<string, unknown>;

    if (!res.ok) {
      throw new SirrError(
        res.status,
        (json["error"] as string) ?? "unknown error",
      );
    }

    return json as T;
  }

  /** Check server health. Does not require authentication. */
  async health(): Promise<{ status: string }> {
    const res = await fetch(`${this.server}/health`);
    return res.json() as Promise<{ status: string }>;
  }

  /**
   * Push a secret to the vault.
   *
   * @param key   Secret key name
   * @param value Secret value
   * @param opts  TTL (seconds) and/or max read count
   */
  async push(key: string, value: string, opts: PushOptions = {}): Promise<void> {
    await this.request("POST", "/secrets", {
      key,
      value,
      ttl_seconds: opts.ttl ?? null,
      max_reads: opts.reads ?? null,
    });
  }

  /**
   * Retrieve a secret by key. Increments the read counter.
   * Returns `null` if the secret does not exist or has expired/burned.
   */
  async get(key: string): Promise<string | null> {
    try {
      const data = await this.request<{ value: string }>(
        "GET",
        `/secrets/${encodeURIComponent(key)}`,
      );
      return data.value;
    } catch (e) {
      if (e instanceof SirrError && e.status === 404) return null;
      throw e;
    }
  }

  /** List metadata for all active secrets. Values are never returned. */
  async list(): Promise<SecretMeta[]> {
    const data = await this.request<{ secrets: SecretMeta[] }>(
      "GET",
      "/secrets",
    );
    return data.secrets;
  }

  /** Delete a secret immediately. Returns true if it existed. */
  async delete(key: string): Promise<boolean> {
    try {
      await this.request("DELETE", `/secrets/${encodeURIComponent(key)}`);
      return true;
    } catch (e) {
      if (e instanceof SirrError && e.status === 404) return false;
      throw e;
    }
  }

  /**
   * Retrieve all secrets and return them as a key→value map.
   * Each GET increments the respective read counter.
   */
  async pullAll(): Promise<Record<string, string>> {
    const metas = await this.list();
    const result: Record<string, string> = {};
    await Promise.all(
      metas.map(async (m) => {
        const value = await this.get(m.key);
        if (value !== null) result[m.key] = value;
      }),
    );
    return result;
  }

  /** Trigger an immediate sweep of expired secrets on the server. */
  async prune(): Promise<number> {
    const data = await this.request<{ pruned: number }>("POST", "/prune");
    return data.pruned;
  }

  /**
   * Inject all vault secrets as process.env variables, then invoke `fn`.
   * Useful in test harnesses and scripts.
   */
  async withSecrets<T>(fn: () => Promise<T>): Promise<T> {
    const secrets = await this.pullAll();
    const originals: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(secrets)) {
      originals[k] = process.env[k];
      process.env[k] = v;
    }
    try {
      return await fn();
    } finally {
      for (const [k, orig] of Object.entries(originals)) {
        if (orig === undefined) delete process.env[k];
        else process.env[k] = orig;
      }
    }
  }
}
