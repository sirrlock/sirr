import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { SirrClient } from "./index";

const mockFetch = jest.fn<typeof fetch>();
global.fetch = mockFetch;

function ok(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

function err(status: number, body: unknown): Response {
  return {
    ok: false,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

const sirr = new SirrClient({ server: "http://localhost:8080", token: "test" });

beforeEach(() => { mockFetch.mockReset(); });

describe("health", () => {
  it("returns status", async () => {
    mockFetch.mockResolvedValueOnce(ok({ status: "ok" }));
    expect(await sirr.health()).toEqual({ status: "ok" });
  });
});

describe("push", () => {
  it("sends POST /secrets with correct body", async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: "FOO" }));
    await sirr.push("FOO", "bar", { ttl: 60, reads: 1 });

    const [url, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://localhost:8080/secrets");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body as string)).toEqual({
      key: "FOO",
      value: "bar",
      ttl_seconds: 60,
      max_reads: 1,
    });
  });

  it("sends null for omitted ttl and reads", async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: "FOO" }));
    await sirr.push("FOO", "bar");
    const [, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(opts.body as string)).toMatchObject({
      ttl_seconds: null,
      max_reads: null,
    });
  });
});

describe("get", () => {
  it("returns value on 200", async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: "FOO", value: "bar" }));
    expect(await sirr.get("FOO")).toBe("bar");
  });

  it("returns null on 404", async () => {
    mockFetch.mockResolvedValueOnce(err(404, { error: "not found" }));
    expect(await sirr.get("FOO")).toBeNull();
  });

  it("throws on non-404 errors", async () => {
    mockFetch.mockResolvedValueOnce(err(500, { error: "server error" }));
    await expect(sirr.get("FOO")).rejects.toThrow("500");
  });

  it("URL-encodes the key", async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: "A B", value: "v" }));
    await sirr.get("A B");
    const [url] = mockFetch.mock.calls[0] as [string];
    expect(url).toContain("A%20B");
  });
});

describe("list", () => {
  it("returns secret metadata array", async () => {
    const meta = [
      {
        key: "FOO",
        created_at: 1,
        expires_at: null,
        max_reads: null,
        read_count: 0,
      },
    ];
    mockFetch.mockResolvedValueOnce(ok({ secrets: meta }));
    expect(await sirr.list()).toEqual(meta);
  });
});

describe("delete", () => {
  it("returns true when secret existed", async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    expect(await sirr.delete("FOO")).toBe(true);
  });

  it("returns false on 404", async () => {
    mockFetch.mockResolvedValueOnce(err(404, { error: "not found" }));
    expect(await sirr.delete("FOO")).toBe(false);
  });
});

describe("prune", () => {
  it("returns pruned count", async () => {
    mockFetch.mockResolvedValueOnce(ok({ pruned: 3 }));
    expect(await sirr.prune()).toBe(3);
  });
});

describe("pullAll", () => {
  it("lists then fetches each value", async () => {
    mockFetch
      .mockResolvedValueOnce(
        ok({
          secrets: [
            {
              key: "A",
              created_at: 0,
              expires_at: null,
              max_reads: null,
              read_count: 0,
            },
            {
              key: "B",
              created_at: 0,
              expires_at: null,
              max_reads: null,
              read_count: 0,
            },
          ],
        }),
      )
      .mockResolvedValueOnce(ok({ key: "A", value: "1" }))
      .mockResolvedValueOnce(ok({ key: "B", value: "2" }));

    const result = await sirr.pullAll();
    expect(result).toEqual({ A: "1", B: "2" });
  });
});

describe("withSecrets", () => {
  it("injects env vars and restores them after", async () => {
    mockFetch
      .mockResolvedValueOnce(
        ok({
          secrets: [
            {
              key: "INJECTED",
              created_at: 0,
              expires_at: null,
              max_reads: null,
              read_count: 0,
            },
          ],
        }),
      )
      .mockResolvedValueOnce(ok({ key: "INJECTED", value: "hello" }));

    delete process.env["INJECTED"];
    let inside = "";

    await sirr.withSecrets(async () => {
      inside = process.env["INJECTED"] ?? "";
    });

    expect(inside).toBe("hello");
    expect(process.env["INJECTED"]).toBeUndefined();
  });

  it("restores env vars even if fn throws", async () => {
    mockFetch
      .mockResolvedValueOnce(
        ok({
          secrets: [
            {
              key: "TEMP",
              created_at: 0,
              expires_at: null,
              max_reads: null,
              read_count: 0,
            },
          ],
        }),
      )
      .mockResolvedValueOnce(ok({ key: "TEMP", value: "x" }));

    delete process.env["TEMP"];
    await expect(
      sirr.withSecrets(async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");

    expect(process.env["TEMP"]).toBeUndefined();
  });
});
