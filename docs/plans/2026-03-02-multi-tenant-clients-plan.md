# Multi-Tenant Client & Integration Updates — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Update all 8 client SDKs and integrations to support the new multi-tenant org-scoped API (`/orgs/{org_id}/secrets/*`, principal auth, `/me` endpoints).

**Architecture:** Each client gains an optional `org` parameter. When set, URL paths swap from `/secrets/*` to `/orgs/{org}/secrets/*` and auth switches from master API key to principal key (Bearer token). The public bucket (`/secrets/*`) remains the default for backward compatibility. Admin methods (org/principal/role management) are added as opt-in.

**Tech Stack:** TypeScript (Node SDK, MCP, OpenClaw), Python (httpx), C# (.NET HttpClient), n8n framework, browser extension (Manifest V3), Rust CLI (clap/reqwest)

---

## Server API Surface Reference

All org-scoped routes require principal key auth (`Authorization: Bearer <principal_key>`).

| Method | Path | Permission |
|--------|------|-----------|
| POST   | `/orgs` | Master only |
| GET    | `/orgs` | Master only |
| DELETE  | `/orgs/{org_id}` | Master only |
| POST   | `/orgs/{org_id}/principals` | Master only |
| GET    | `/orgs/{org_id}/principals` | Master only |
| DELETE  | `/orgs/{org_id}/principals/{id}` | Master only |
| POST   | `/orgs/{org_id}/roles` | Master only |
| GET    | `/orgs/{org_id}/roles` | Master only |
| DELETE  | `/orgs/{org_id}/roles/{name}` | Master only |
| GET    | `/me` | Any principal |
| PATCH  | `/me` | Any principal |
| POST   | `/me/keys` | Any principal |
| DELETE  | `/me/keys/{key_id}` | Any principal |
| POST   | `/orgs/{org_id}/secrets` | CreateSecret |
| GET    | `/orgs/{org_id}/secrets` | ListSecrets |
| GET    | `/orgs/{org_id}/secrets/{key}` | ReadOrg or ReadMy |
| HEAD   | `/orgs/{org_id}/secrets/{key}` | ReadOrg or ReadMy |
| PATCH  | `/orgs/{org_id}/secrets/{key}` | PatchOrg or PatchMy |
| DELETE  | `/orgs/{org_id}/secrets/{key}` | DeleteOrg or DeleteMy |
| POST   | `/orgs/{org_id}/prune` | Prune |
| GET    | `/orgs/{org_id}/audit` | AuditRead |
| POST   | `/orgs/{org_id}/webhooks` | WebhookManage |
| GET    | `/orgs/{org_id}/webhooks` | WebhookManage |
| DELETE  | `/orgs/{org_id}/webhooks/{id}` | WebhookManage |

---

## Task 1: Node SDK — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/node/src/index.ts`
- Modify: `/Users/e/dev/sirr/node/src/index.test.ts`
- Modify: `/Users/e/dev/sirr/node/README.md`

**Context:** The Node SDK has a `SirrClient` class with a private `request<T>(method, path, body?)` helper. All methods call `this.request(method, '/secrets/...')`. The constructor takes `{ server, token }`. Zero external dependencies — uses native `fetch`.

**Step 1: Write the failing test**

In `index.test.ts`, add a test that constructs `SirrClient` with `org` and verifies the URL prefix changes:

```typescript
describe('org-scoped client', () => {
  it('prefixes secret paths with /orgs/{org}', async () => {
    const client = new SirrClient({
      server: 'http://localhost:8080',
      token: 'principal-key',
      org: 'my-org',
    });

    // Mock fetch to capture the URL
    const originalFetch = globalThis.fetch;
    let capturedUrl = '';
    globalThis.fetch = async (url: any, init?: any) => {
      capturedUrl = typeof url === 'string' ? url : url.toString();
      return new Response(JSON.stringify({ value: 'hello' }), { status: 200 });
    };

    try {
      await client.get('test-key');
      expect(capturedUrl).toBe('http://localhost:8080/orgs/my-org/secrets/test-key');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('uses /secrets prefix when org is not set', async () => {
    const client = new SirrClient({
      server: 'http://localhost:8080',
      token: 'master-key',
    });

    const originalFetch = globalThis.fetch;
    let capturedUrl = '';
    globalThis.fetch = async (url: any, init?: any) => {
      capturedUrl = typeof url === 'string' ? url : url.toString();
      return new Response(JSON.stringify({ value: 'hello' }), { status: 200 });
    };

    try {
      await client.get('test-key');
      expect(capturedUrl).toBe('http://localhost:8080/secrets/test-key');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/e/dev/sirr/node && npm test`
Expected: FAIL — `SirrClient` constructor doesn't accept `org`

**Step 3: Implement org support**

In `index.ts`:

1. Add `org?: string` to the options interface:
```typescript
export interface SirrOptions {
  server: string;
  token: string;
  org?: string;  // When set, routes through /orgs/{org}/secrets/*
}
```

2. Store `org` in the constructor:
```typescript
private org?: string;

constructor(opts: SirrOptions) {
  this.server = opts.server.replace(/\/+$/, '');
  this.token = opts.token;
  this.org = opts.org;
}
```

3. Add a private `secretsPath(key?: string)` helper:
```typescript
private secretsPath(key?: string): string {
  const base = this.org ? `/orgs/${this.org}/secrets` : '/secrets';
  return key ? `${base}/${key}` : base;
}
```

4. Replace all hardcoded `/secrets/...` paths in existing methods (`push`, `get`, `head`, `list`, `del`, `patch`, `share`, `prune`) with `this.secretsPath(key)`.

5. Add equivalent helpers for audit/webhooks:
```typescript
private auditPath(): string {
  return this.org ? `/orgs/${this.org}/audit` : '/audit';
}
private webhooksPath(id?: string): string {
  const base = this.org ? `/orgs/${this.org}/webhooks` : '/webhooks';
  return id ? `${base}/${id}` : base;
}
private prunePath(): string {
  return this.org ? `/orgs/${this.org}/prune` : '/prune';
}
```

6. Add `/me` methods:
```typescript
async me(): Promise<any> {
  return this.request('GET', '/me');
}

async updateMe(body: { display_name?: string; metadata?: Record<string, string> }): Promise<any> {
  return this.request('PATCH', '/me', body);
}

async createKey(body: { name: string; expires_at?: string }): Promise<any> {
  return this.request('POST', '/me/keys', body);
}

async deleteKey(keyId: string): Promise<void> {
  await this.request('DELETE', `/me/keys/${keyId}`);
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/e/dev/sirr/node && npm test`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/e/dev/sirr/node
git add src/index.ts src/index.test.ts
git commit -m "feat: add multi-tenant org support with /me endpoints"
```

---

## Task 2: Node SDK — Add Admin Methods (Org/Principal/Role Management)

**Files:**
- Modify: `/Users/e/dev/sirr/node/src/index.ts`
- Modify: `/Users/e/dev/sirr/node/src/index.test.ts`

**Context:** These are master-key-only operations. They should be added to the same `SirrClient` class. The caller uses a master key token with `org` unset.

**Step 1: Write the failing test**

```typescript
describe('admin methods', () => {
  let client: SirrClient;
  let capturedMethod = '';
  let capturedUrl = '';
  let capturedBody: any = null;

  beforeEach(() => {
    client = new SirrClient({ server: 'http://localhost:8080', token: 'master-key' });
    globalThis.fetch = async (url: any, init?: any) => {
      capturedUrl = typeof url === 'string' ? url : url.toString();
      capturedMethod = init?.method ?? 'GET';
      capturedBody = init?.body ? JSON.parse(init.body) : null;
      return new Response(JSON.stringify({ id: 'org-1' }), { status: 200 });
    };
  });

  it('createOrg sends POST /orgs', async () => {
    await client.createOrg({ name: 'test-org' });
    expect(capturedMethod).toBe('POST');
    expect(capturedUrl).toBe('http://localhost:8080/orgs');
  });

  it('listOrgs sends GET /orgs', async () => {
    await client.listOrgs();
    expect(capturedMethod).toBe('GET');
    expect(capturedUrl).toBe('http://localhost:8080/orgs');
  });

  it('deleteOrg sends DELETE /orgs/{id}', async () => {
    await client.deleteOrg('org-1');
    expect(capturedMethod).toBe('DELETE');
    expect(capturedUrl).toBe('http://localhost:8080/orgs/org-1');
  });

  it('createPrincipal sends POST /orgs/{org}/principals', async () => {
    await client.createPrincipal('org-1', { display_name: 'Alice', role: 'admin' });
    expect(capturedMethod).toBe('POST');
    expect(capturedUrl).toBe('http://localhost:8080/orgs/org-1/principals');
  });

  it('listPrincipals sends GET /orgs/{org}/principals', async () => {
    await client.listPrincipals('org-1');
    expect(capturedUrl).toBe('http://localhost:8080/orgs/org-1/principals');
  });

  it('deletePrincipal sends DELETE /orgs/{org}/principals/{id}', async () => {
    await client.deletePrincipal('org-1', 'princ-1');
    expect(capturedUrl).toBe('http://localhost:8080/orgs/org-1/principals/princ-1');
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/e/dev/sirr/node && npm test`
Expected: FAIL — methods don't exist

**Step 3: Implement admin methods**

In `index.ts`, add to `SirrClient`:

```typescript
// ── Org management (master key only) ─────────────────────────────
async createOrg(body: { name: string; metadata?: Record<string, string> }): Promise<any> {
  return this.request('POST', '/orgs', body);
}

async listOrgs(): Promise<any> {
  return this.request('GET', '/orgs');
}

async deleteOrg(orgId: string): Promise<void> {
  await this.request('DELETE', `/orgs/${orgId}`);
}

// ── Principal management (master key only) ───────────────────────
async createPrincipal(orgId: string, body: { display_name?: string; role: string }): Promise<any> {
  return this.request('POST', `/orgs/${orgId}/principals`, body);
}

async listPrincipals(orgId: string): Promise<any> {
  return this.request('GET', `/orgs/${orgId}/principals`);
}

async deletePrincipal(orgId: string, principalId: string): Promise<void> {
  await this.request('DELETE', `/orgs/${orgId}/principals/${principalId}`);
}

// ── Role management (master key only) ────────────────────────────
async createRole(orgId: string, body: { name: string; permissions: string[] }): Promise<any> {
  return this.request('POST', `/orgs/${orgId}/roles`, body);
}

async listRoles(orgId: string): Promise<any> {
  return this.request('GET', `/orgs/${orgId}/roles`);
}

async deleteRole(orgId: string, roleName: string): Promise<void> {
  await this.request('DELETE', `/orgs/${orgId}/roles/${roleName}`);
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/e/dev/sirr/node && npm test`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/e/dev/sirr/node
git add src/index.ts src/index.test.ts
git commit -m "feat: add org, principal, and role admin methods"
```

---

## Task 3: Python SDK — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/python/src/sirr/_client.py`
- Modify: `/Users/e/dev/sirr/python/src/sirr/_async_client.py`
- Modify: `/Users/e/dev/sirr/python/src/sirr/_transport.py`
- Modify: `/Users/e/dev/sirr/python/tests/test_client.py`
- Modify: `/Users/e/dev/sirr/python/tests/test_async_client.py`

**Context:** The Python SDK has sync (`SirrClient`) and async (`AsyncSirrClient`) clients. Both use `self._base` (URL prefix) and shared transport helpers in `_transport.py`. The `_base` is set in the constructor as `normalize_server(server)`. Methods call `self._http.get(f"{self._base}/secrets/{key}")` etc.

**Step 1: Write the failing test**

In `tests/test_client.py`:

```python
def test_org_scoped_urls(respx_mock):
    """When org is set, secrets go through /orgs/{org}/secrets/*."""
    client = SirrClient(server="http://localhost:8080", token="pk", org="my-org")
    respx_mock.get("http://localhost:8080/orgs/my-org/secrets/foo").mock(
        return_value=httpx.Response(200, json={"value": "bar"})
    )
    result = client.get("foo")
    assert result == "bar"


def test_no_org_uses_public_bucket(respx_mock):
    """Without org, secrets go through /secrets/*."""
    client = SirrClient(server="http://localhost:8080", token="mk")
    respx_mock.get("http://localhost:8080/secrets/foo").mock(
        return_value=httpx.Response(200, json={"value": "bar"})
    )
    result = client.get("foo")
    assert result == "bar"
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/e/dev/sirr/python && pytest tests/test_client.py -v -k "org"`
Expected: FAIL — `org` parameter not accepted

**Step 3: Implement org support**

In `_transport.py`, add a helper:

```python
def secrets_prefix(base: str, org: str | None) -> str:
    """Return the URL prefix for secret operations."""
    if org:
        return f"{base}/orgs/{org}/secrets"
    return f"{base}/secrets"

def audit_prefix(base: str, org: str | None) -> str:
    if org:
        return f"{base}/orgs/{org}/audit"
    return f"{base}/audit"

def webhooks_prefix(base: str, org: str | None) -> str:
    if org:
        return f"{base}/orgs/{org}/webhooks"
    return f"{base}/webhooks"

def prune_prefix(base: str, org: str | None) -> str:
    if org:
        return f"{base}/orgs/{org}/prune"
    return f"{base}/prune"
```

In `_client.py`:

1. Add `org: str | None = None` to `__init__`:
```python
def __init__(self, server: str, token: str, org: str | None = None):
    self._base = normalize_server(server)
    self._org = org
    # ... existing httpx.Client setup
```

2. Add a private property:
```python
@property
def _secrets(self) -> str:
    return secrets_prefix(self._base, self._org)
```

3. Replace `f"{self._base}/secrets/..."` with `f"{self._secrets}/..."` in all methods.

4. Add `/me` methods:
```python
def me(self) -> dict:
    resp = self._http.get(f"{self._base}/me", headers=build_headers(self._token))
    return handle_response(resp)

def update_me(self, **kwargs) -> dict:
    resp = self._http.patch(f"{self._base}/me", json=kwargs, headers=build_headers(self._token))
    return handle_response(resp)

def create_key(self, name: str, expires_at: str | None = None) -> dict:
    body = {"name": name}
    if expires_at:
        body["expires_at"] = expires_at
    resp = self._http.post(f"{self._base}/me/keys", json=body, headers=build_headers(self._token))
    return handle_response(resp)

def delete_key(self, key_id: str) -> None:
    resp = self._http.delete(f"{self._base}/me/keys/{key_id}", headers=build_headers(self._token))
    handle_response(resp)
```

5. Repeat the same changes in `_async_client.py` (identical pattern but with `async/await`).

**Step 4: Run test to verify it passes**

Run: `cd /Users/e/dev/sirr/python && pytest tests/ -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/e/dev/sirr/python
git add src/sirr/_client.py src/sirr/_async_client.py src/sirr/_transport.py tests/
git commit -m "feat: add multi-tenant org support with /me endpoints"
```

---

## Task 4: Python SDK — Add Admin Methods

**Files:**
- Modify: `/Users/e/dev/sirr/python/src/sirr/_client.py`
- Modify: `/Users/e/dev/sirr/python/src/sirr/_async_client.py`
- Modify: `/Users/e/dev/sirr/python/tests/test_client.py`

**Step 1: Write the failing test**

```python
def test_create_org(respx_mock):
    client = SirrClient(server="http://localhost:8080", token="mk")
    respx_mock.post("http://localhost:8080/orgs").mock(
        return_value=httpx.Response(200, json={"id": "org-1", "name": "test"})
    )
    result = client.create_org(name="test")
    assert result["id"] == "org-1"

def test_create_principal(respx_mock):
    client = SirrClient(server="http://localhost:8080", token="mk")
    respx_mock.post("http://localhost:8080/orgs/org-1/principals").mock(
        return_value=httpx.Response(200, json={"id": "p-1"})
    )
    result = client.create_principal("org-1", role="admin")
    assert result["id"] == "p-1"
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/e/dev/sirr/python && pytest tests/test_client.py -v -k "create_org or create_principal"`
Expected: FAIL

**Step 3: Implement admin methods**

In `_client.py`:

```python
# ── Org management (master key only) ──────────────────────────────
def create_org(self, name: str, **kwargs) -> dict:
    resp = self._http.post(f"{self._base}/orgs", json={"name": name, **kwargs}, headers=build_headers(self._token))
    return handle_response(resp)

def list_orgs(self) -> list:
    resp = self._http.get(f"{self._base}/orgs", headers=build_headers(self._token))
    return handle_response(resp)

def delete_org(self, org_id: str) -> None:
    resp = self._http.delete(f"{self._base}/orgs/{org_id}", headers=build_headers(self._token))
    handle_response(resp)

# ── Principal management (master key only) ────────────────────────
def create_principal(self, org_id: str, role: str, **kwargs) -> dict:
    resp = self._http.post(f"{self._base}/orgs/{org_id}/principals", json={"role": role, **kwargs}, headers=build_headers(self._token))
    return handle_response(resp)

def list_principals(self, org_id: str) -> list:
    resp = self._http.get(f"{self._base}/orgs/{org_id}/principals", headers=build_headers(self._token))
    return handle_response(resp)

def delete_principal(self, org_id: str, principal_id: str) -> None:
    resp = self._http.delete(f"{self._base}/orgs/{org_id}/principals/{principal_id}", headers=build_headers(self._token))
    handle_response(resp)

# ── Role management (master key only) ─────────────────────────────
def create_role(self, org_id: str, name: str, permissions: list[str]) -> dict:
    resp = self._http.post(f"{self._base}/orgs/{org_id}/roles", json={"name": name, "permissions": permissions}, headers=build_headers(self._token))
    return handle_response(resp)

def list_roles(self, org_id: str) -> list:
    resp = self._http.get(f"{self._base}/orgs/{org_id}/roles", headers=build_headers(self._token))
    return handle_response(resp)

def delete_role(self, org_id: str, role_name: str) -> None:
    resp = self._http.delete(f"{self._base}/orgs/{org_id}/roles/{role_name}", headers=build_headers(self._token))
    handle_response(resp)
```

Mirror all methods in `_async_client.py` with `async def` + `await`.

**Step 4: Run tests**

Run: `cd /Users/e/dev/sirr/python && pytest tests/ -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/e/dev/sirr/python
git add src/sirr/ tests/
git commit -m "feat: add org, principal, and role admin methods"
```

---

## Task 5: .NET SDK — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/dotnet/src/Sirr.Client/SirrOptions.cs`
- Modify: `/Users/e/dev/sirr/dotnet/src/Sirr.Client/ISirrClient.cs`
- Modify: `/Users/e/dev/sirr/dotnet/src/Sirr.Client/SirrClient.cs`
- Modify: `/Users/e/dev/sirr/dotnet/tests/Sirr.Client.Tests/` (test files)

**Context:** The .NET SDK uses `SirrOptions { Server, Token }` for config. `SirrClient` has a private `SendAsync<T>(HttpMethod, path, body?)` helper. The base address is set via `HttpClient.BaseAddress`. Uses DI registration via `AddSirr()` extension.

**Step 1: Write the failing test**

```csharp
[Fact]
public async Task OrgScopedClient_PrefixesSecretsPath()
{
    var handler = new MockHttpHandler((req, _) =>
    {
        Assert.Equal("/orgs/my-org/secrets/foo", req.RequestUri?.PathAndQuery);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"value\":\"bar\"}", Encoding.UTF8, "application/json")
        });
    });

    var client = new SirrClient(new SirrOptions
    {
        Server = "http://localhost:8080",
        Token = "pk",
        Org = "my-org"
    }, new HttpClient(handler));

    var result = await client.GetAsync("foo");
    Assert.Equal("bar", result);
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/e/dev/sirr/dotnet && dotnet test`
Expected: FAIL — `Org` property doesn't exist on `SirrOptions`

**Step 3: Implement org support**

In `SirrOptions.cs`, add:
```csharp
/// <summary>
/// When set, routes secret operations through /orgs/{Org}/secrets/*.
/// Use with a principal key token instead of the master API key.
/// </summary>
public string? Org { get; set; }
```

In `SirrClient.cs`:

1. Store org from options:
```csharp
private readonly string? _org;

public SirrClient(SirrOptions options, HttpClient httpClient)
{
    _org = options.Org;
    // ... existing setup
}
```

2. Add path helpers:
```csharp
private string SecretsPath(string? key = null)
{
    var basePath = _org != null ? $"/orgs/{_org}/secrets" : "/secrets";
    return key != null ? $"{basePath}/{key}" : basePath;
}

private string AuditPath() => _org != null ? $"/orgs/{_org}/audit" : "/audit";
private string WebhooksPath(string? id = null)
{
    var basePath = _org != null ? $"/orgs/{_org}/webhooks" : "/webhooks";
    return id != null ? $"{basePath}/{id}" : basePath;
}
private string PrunePath() => _org != null ? $"/orgs/{_org}/prune" : "/prune";
```

3. Replace all hardcoded `/secrets/...` with `SecretsPath(key)`.

4. Add `/me` methods to `ISirrClient` and `SirrClient`:
```csharp
// ISirrClient.cs
Task<MeResponse> GetMeAsync(CancellationToken ct = default);
Task<MeResponse> UpdateMeAsync(UpdateMeRequest request, CancellationToken ct = default);
Task<KeyCreateResult> CreateKeyAsync(CreateKeyRequest request, CancellationToken ct = default);
Task DeleteKeyAsync(string keyId, CancellationToken ct = default);

// SirrClient.cs
public async Task<MeResponse> GetMeAsync(CancellationToken ct = default)
    => await SendAsync<MeResponse>(HttpMethod.Get, "/me", ct: ct);

public async Task<MeResponse> UpdateMeAsync(UpdateMeRequest request, CancellationToken ct = default)
    => await SendAsync<MeResponse>(HttpMethod.Patch, "/me", request, ct);

public async Task<KeyCreateResult> CreateKeyAsync(CreateKeyRequest request, CancellationToken ct = default)
    => await SendAsync<KeyCreateResult>(HttpMethod.Post, "/me/keys", request, ct);

public async Task DeleteKeyAsync(string keyId, CancellationToken ct = default)
    => await SendAsync(HttpMethod.Delete, $"/me/keys/{keyId}", ct: ct);
```

5. Add model classes (new file or in existing models):
```csharp
public record MeResponse(string PrincipalId, string OrgId, string DisplayName, string Role);
public record UpdateMeRequest(string? DisplayName = null, Dictionary<string, string>? Metadata = null);
public record CreateKeyRequest(string Name, string? ExpiresAt = null);
public record KeyCreateResult(string KeyId, string RawKey);
```

**Step 4: Run tests**

Run: `cd /Users/e/dev/sirr/dotnet && dotnet test`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/e/dev/sirr/dotnet
git add src/ tests/
git commit -m "feat: add multi-tenant org support with /me endpoints"
```

---

## Task 6: .NET SDK — Add Admin Methods

**Files:**
- Modify: `/Users/e/dev/sirr/dotnet/src/Sirr.Client/ISirrClient.cs`
- Modify: `/Users/e/dev/sirr/dotnet/src/Sirr.Client/SirrClient.cs`
- Modify: `/Users/e/dev/sirr/dotnet/tests/Sirr.Client.Tests/`

**Step 1: Write failing tests for org/principal/role CRUD**

Test that `CreateOrgAsync`, `ListOrgsAsync`, `DeleteOrgAsync`, `CreatePrincipalAsync`, etc. hit the correct paths.

**Step 2: Run test to verify it fails**

Run: `cd /Users/e/dev/sirr/dotnet && dotnet test`

**Step 3: Implement admin methods**

Add to `ISirrClient` and `SirrClient`:

```csharp
// Org
Task<OrgResponse> CreateOrgAsync(CreateOrgRequest request, CancellationToken ct = default);
Task<List<OrgResponse>> ListOrgsAsync(CancellationToken ct = default);
Task DeleteOrgAsync(string orgId, CancellationToken ct = default);

// Principal
Task<PrincipalResponse> CreatePrincipalAsync(string orgId, CreatePrincipalRequest request, CancellationToken ct = default);
Task<List<PrincipalResponse>> ListPrincipalsAsync(string orgId, CancellationToken ct = default);
Task DeletePrincipalAsync(string orgId, string principalId, CancellationToken ct = default);

// Role
Task<RoleResponse> CreateRoleAsync(string orgId, CreateRoleRequest request, CancellationToken ct = default);
Task<List<RoleResponse>> ListRolesAsync(string orgId, CancellationToken ct = default);
Task DeleteRoleAsync(string orgId, string roleName, CancellationToken ct = default);
```

Implementation follows the same `SendAsync` pattern:
```csharp
public async Task<OrgResponse> CreateOrgAsync(CreateOrgRequest request, CancellationToken ct = default)
    => await SendAsync<OrgResponse>(HttpMethod.Post, "/orgs", request, ct);

public async Task<PrincipalResponse> CreatePrincipalAsync(string orgId, CreatePrincipalRequest request, CancellationToken ct = default)
    => await SendAsync<PrincipalResponse>(HttpMethod.Post, $"/orgs/{orgId}/principals", request, ct);
// etc.
```

**Step 4: Run tests, Step 5: Commit**

```bash
cd /Users/e/dev/sirr/dotnet && dotnet test
git add src/ tests/ && git commit -m "feat: add org, principal, and role admin methods"
```

---

## Task 7: MCP Server — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/mcp/src/index.ts`
- Modify: `/Users/e/dev/sirr/mcp/src/helpers.ts`
- Modify: `/Users/e/dev/sirr/mcp/src/helpers.test.ts`

**Context:** The MCP server uses env vars `SIRR_SERVER` and `SIRR_TOKEN`. It has a `sirrRequest(method, path, body?)` helper and `fetchWithTimeout()`. There are 13 MCP tools defined as `server.tool(...)` calls. The MCP server acts as a bridge — it doesn't manage orgs itself but needs to route through the correct prefix.

**Step 1: Write the failing test**

In `helpers.test.ts`, test that the `secretsPath` helper works:

```typescript
describe('secretsPath', () => {
  it('returns /orgs/{org}/secrets/{key} when SIRR_ORG is set', () => {
    process.env.SIRR_ORG = 'my-org';
    expect(secretsPath('foo')).toBe('/orgs/my-org/secrets/foo');
    delete process.env.SIRR_ORG;
  });

  it('returns /secrets/{key} when SIRR_ORG is not set', () => {
    delete process.env.SIRR_ORG;
    expect(secretsPath('foo')).toBe('/secrets/foo');
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/e/dev/sirr/mcp && npm test`

**Step 3: Implement org support**

In `helpers.ts`, add path helpers:

```typescript
export function secretsPath(key?: string): string {
  const org = process.env.SIRR_ORG;
  const base = org ? `/orgs/${org}/secrets` : '/secrets';
  return key ? `${base}/${key}` : base;
}

export function auditPath(): string {
  const org = process.env.SIRR_ORG;
  return org ? `/orgs/${org}/audit` : '/audit';
}

export function webhooksPath(id?: string): string {
  const org = process.env.SIRR_ORG;
  const base = org ? `/orgs/${org}/webhooks` : '/webhooks';
  return id ? `${base}/${id}` : base;
}

export function prunePath(): string {
  const org = process.env.SIRR_ORG;
  return org ? `/orgs/${org}/prune` : '/prune';
}
```

In `index.ts`:
1. Replace all hardcoded `/secrets/...` with `secretsPath(key)` from helpers.
2. Replace `/audit`, `/webhooks/...`, `/prune` with their helpers.
3. Add `/me` tools:

```typescript
server.tool('sirr_me', 'Get current principal info', {}, async () => {
  const result = await sirrRequest('GET', '/me');
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

server.tool('sirr_create_key', 'Create a new API key for current principal', {
  name: z.string(),
  expires_at: z.string().optional(),
}, async ({ name, expires_at }) => {
  const result = await sirrRequest('POST', '/me/keys', { name, expires_at });
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});
```

**Step 4: Run tests, Step 5: Commit**

```bash
cd /Users/e/dev/sirr/mcp && npm test
git add src/ && git commit -m "feat: add SIRR_ORG env var for multi-tenant support"
```

---

## Task 8: n8n Node — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/n8n/nodes/Sirr/Sirr.node.ts`
- Modify: `/Users/e/dev/sirr/n8n/credentials/SirrApi.credentials.ts`

**Context:** The n8n node uses `this.helpers.httpRequestWithAuthentication('sirrApi', options)` where `options.url` is constructed from the credential's `serverUrl`. The credential type does generic auth (Bearer header injection). Operations are defined as resources (Secret, Webhook, Audit) with operations (create, get, list, delete, etc.).

**Step 1: Add org field to credentials**

In `SirrApi.credentials.ts`, add an optional `org` field:

```typescript
{
  displayName: 'Organization ID',
  name: 'org',
  type: 'string',
  default: '',
  description: 'Optional org ID for multi-tenant mode. Leave empty for public bucket.',
}
```

**Step 2: Update node to use org-scoped paths**

In `Sirr.node.ts`:

1. Add a helper method to build the secrets URL:
```typescript
function buildUrl(serverUrl: string, org: string | undefined, path: string): string {
  const base = serverUrl.replace(/\/+$/, '');
  if (org && path.startsWith('/secrets')) {
    return `${base}/orgs/${org}${path}`;
  }
  if (org && path.startsWith('/audit')) {
    return `${base}/orgs/${org}${path}`;
  }
  if (org && path.startsWith('/webhooks')) {
    return `${base}/orgs/${org}${path}`;
  }
  if (org && path.startsWith('/prune')) {
    return `${base}/orgs/${org}${path}`;
  }
  return `${base}${path}`;
}
```

2. In the `execute` method, read `org` from credentials and use `buildUrl()`:
```typescript
const credentials = await this.getCredentials('sirrApi');
const serverUrl = credentials.serverUrl as string;
const org = (credentials.org as string) || undefined;
// ... then all URL constructions use buildUrl(serverUrl, org, '/secrets/...')
```

3. Add new resource "Principal" with operations: `me` (get), `updateMe` (patch), `createKey` (post), `deleteKey` (delete).

**Step 3: Commit**

```bash
cd /Users/e/dev/sirr/n8n
git add nodes/ credentials/
git commit -m "feat: add org support and principal self-service operations"
```

---

## Task 9: OpenClaw Skill — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/openclaw/src/index.ts`
- Modify: `/Users/e/dev/sirr/openclaw/skill.json`

**Context:** OpenClaw has 13 exported functions (`pushSecret`, `getSecret`, etc.) that take a `SirrConfig { serverUrl, token }` and build URLs manually with `${config.serverUrl}/secrets/...`. Uses native `fetch`.

**Step 1: Update SirrConfig**

```typescript
export interface SirrConfig {
  serverUrl: string;
  token: string;
  org?: string;  // optional org for multi-tenant
}
```

**Step 2: Add path helpers**

```typescript
function secretsUrl(config: SirrConfig, key?: string): string {
  const base = config.serverUrl.replace(/\/+$/, '');
  const prefix = config.org ? `/orgs/${config.org}/secrets` : '/secrets';
  return key ? `${base}${prefix}/${key}` : `${base}${prefix}`;
}
```

**Step 3: Replace all hardcoded URLs**

Replace all `${config.serverUrl}/secrets/...` with `secretsUrl(config, key)` across all 13 functions.

**Step 4: Add /me functions**

```typescript
export async function getMe(config: SirrConfig): Promise<any> {
  return request(config, { method: 'GET', path: '/me' });
}

export async function createKey(config: SirrConfig, name: string): Promise<any> {
  return request(config, { method: 'POST', path: '/me/keys', body: { name } });
}
```

**Step 5: Update `skill.json`**

Add `org` to the config schema and add new tool entries for `getMe`, `createKey`.

**Step 6: Commit**

```bash
cd /Users/e/dev/sirr/openclaw
git add src/index.ts skill.json
git commit -m "feat: add multi-tenant org support"
```

---

## Task 10: Browser Extension — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/sirr-extension/background.js`
- Modify: `/Users/e/dev/sirr/sirr-extension/options.html`
- Modify: `/Users/e/dev/sirr/sirr-extension/options.js`

**Context:** The extension stores settings in `chrome.storage.local`: `{ server, token }`. `background.js` has 3 HTTP functions: `storeSecret()`, `readSecret()`, `burnSecret()`. URLs are built as `${settings.server}/secrets/...`.

**Step 1: Add org to settings UI**

In `options.html`, add a new field after the token field:

```html
<label for="org">Organization ID (optional, for multi-tenant)</label>
<input type="text" id="org" placeholder="Leave empty for public bucket">
```

In `options.js`, load/save the `org` field alongside `server` and `token`.

**Step 2: Update background.js**

Add a helper:
```javascript
function secretsUrl(settings, key) {
  const base = settings.server.replace(/\/+$/, '');
  if (settings.org) {
    return key ? `${base}/orgs/${settings.org}/secrets/${key}` : `${base}/orgs/${settings.org}/secrets`;
  }
  return key ? `${base}/secrets/${key}` : `${base}/secrets`;
}
```

Replace all `${settings.server}/secrets/...` with `secretsUrl(settings, key)` in `storeSecret()`, `readSecret()`, `burnSecret()`.

**Step 3: Commit**

```bash
cd /Users/e/dev/sirr/sirr-extension
git add background.js options.html options.js
git commit -m "feat: add org support for multi-tenant mode"
```

---

## Task 11: Rust CLI (`sirr`) — Add Org Support

**Files:**
- Modify: `/Users/e/dev/sirr/sirr/.claude/worktrees/multi-tenant/crates/sirr/src/main.rs`

**Context:** The `sirr` CLI uses clap + reqwest. It reads `SIRR_SERVER` and `SIRR_TOKEN` env vars. URLs are built as `format!("{}/secrets/{}", server, key)`. This is the same monorepo we're working in.

**Step 1: Add `--org` global option and `SIRR_ORG` env var**

```rust
#[derive(Parser)]
#[command(name = "sirr", about = "Sirr CLI client")]
struct Cli {
    /// Sirr server URL
    #[arg(long, env = "SIRR_SERVER", global = true)]
    server: String,

    /// API token (master key or principal key)
    #[arg(long, env = "SIRR_TOKEN", global = true)]
    token: String,

    /// Org ID for multi-tenant mode (uses /orgs/{org}/secrets/*)
    #[arg(long, env = "SIRR_ORG", global = true)]
    org: Option<String>,

    #[command(subcommand)]
    command: Commands,
}
```

**Step 2: Add path helpers**

```rust
fn secrets_path(org: &Option<String>, key: Option<&str>) -> String {
    match (org, key) {
        (Some(o), Some(k)) => format!("/orgs/{o}/secrets/{k}"),
        (Some(o), None) => format!("/orgs/{o}/secrets"),
        (None, Some(k)) => format!("/secrets/{k}"),
        (None, None) => "/secrets".to_string(),
    }
}
```

**Step 3: Replace all hardcoded `/secrets/...` paths**

Update all subcommand handlers (`push`, `get`, `pull`, `run`, `share`, `list`, `delete`, `prune`, `webhooks`, `audit`) to use `secrets_path(&cli.org, Some(&key))`.

**Step 4: Add `me` subcommand**

```rust
/// Show current principal info
Me,

/// Manage API keys
Keys {
    #[command(subcommand)]
    action: KeysAction,
},
```

```rust
#[derive(Subcommand)]
enum KeysAction {
    /// Create a new key
    Create { name: String },
    /// Delete a key
    Delete { key_id: String },
}
```

**Step 5: Build and test**

```bash
cargo build --bin sirr
cargo test -p sirr
```

**Step 6: Commit**

```bash
git add crates/sirr/src/main.rs
git commit -m "feat(cli): add --org flag and /me subcommands for multi-tenant"
```

---

## Task 12: Update READMEs and Documentation

**Files:**
- Modify: `/Users/e/dev/sirr/node/README.md`
- Modify: `/Users/e/dev/sirr/python/README.md`
- Modify: `/Users/e/dev/sirr/dotnet/README.md`
- Modify: `/Users/e/dev/sirr/mcp/README.md`
- Modify: `/Users/e/dev/sirr/n8n/README.md`
- Modify: `/Users/e/dev/sirr/openclaw/README.md`
- Modify: `/Users/e/dev/sirr/sirr-extension/README.md`
- Modify: `/Users/e/dev/sirr/sirr/README.md`

**For each README:**

1. Add a "Multi-Tenant / Org Mode" section showing:
   - How to configure the `org` parameter
   - Example usage (org-scoped push/get)
   - `/me` endpoints
   - Admin methods (for SDKs that have them)

2. Update existing examples to note that they show "public bucket" mode.

3. Commit each repo separately:

```bash
# For each repo:
git add README.md && git commit -m "docs: add multi-tenant usage examples"
```

---

## Execution Notes

**Dependency order:** Tasks 1-2 (Node), 3-4 (Python), 5-6 (.NET) can run in parallel. Task 7 (MCP), 8 (n8n), 9 (OpenClaw), 10 (Extension) can run in parallel. Task 11 (CLI) is in the same monorepo so should run after pen test merge. Task 12 (docs) runs last.

**Common pattern across all clients:**
1. Add optional `org` config param
2. Build a `secretsPath(key?)` helper that conditionally prefixes `/orgs/{org}`
3. Replace hardcoded `/secrets/...` with the helper
4. Add `/me` methods
5. Optionally add admin methods (org/principal/role CRUD)
6. Update tests and docs

**Environment variables for non-SDK integrations:**
- `SIRR_ORG` — the org ID (MCP server, CLI)
- Credential field `org` (n8n)
- Config object `org` (OpenClaw)
- Settings UI `org` (browser extension)
