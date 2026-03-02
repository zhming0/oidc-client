# oidc-client

OpenID Connect / OAuth 2.0 client library for Clojure.

Plain data in, plain data out. Server metadata and client configuration are regular Clojure maps. No custom types, no macros, no global state.

Based on [panva/openid-client](https://github.com/panva/openid-client) by Filip Skokan — the reference OpenID Connect client implementation for JavaScript/TypeScript.

## Dependencies

- [org.babashka/http-client](https://github.com/babashka/http-client) for HTTP
- [metosin/jsonista](https://github.com/metosin/jsonista) for JSON

## Installation

Add to your `deps.edn`:

```clojure
oidc-client {:local/root "/path/to/oidc-client"}
```

## Quick start

```clojure
(require '[oidc-client.core :as oidc])

;; 1. Discover server metadata
(def server-meta (oidc/discover "https://accounts.google.com"))

;; 2. Build a client configuration
(def config (oidc/configuration server-meta "my-client-id"
                                {:client-secret "my-secret"}))

;; 3. Build an authorization URL and redirect the user
(def verifier (oidc/random-pkce-code-verifier))

(def auth-url
  (oidc/build-authorization-url config
    {:redirect_uri          "http://localhost:8080/callback"
     :scope                 "openid email profile"
     :state                 (oidc/random-state)
     :nonce                 (oidc/random-nonce)
     :code_challenge        (oidc/pkce-code-challenge verifier)
     :code_challenge_method "S256"}))

;; 4. After the user is redirected back, exchange the code for tokens
(def tokens
  (oidc/authorization-code-grant config
    {:code          "authorization-code-from-callback"
     :redirect_uri  "http://localhost:8080/callback"
     :code_verifier verifier}))

;; 5. Fetch user info
(def userinfo (oidc/fetch-userinfo config (:access_token tokens)))
```

## API

### Discovery

- `(discover issuer)` — Fetch the `.well-known/openid-configuration` document. Returns a keyword-keyed map of server metadata.

### Configuration

- `(configuration server-metadata client-id)` — Build a client config with no client secret (public client).
- `(configuration server-metadata client-id opts)` — Build a client config. `opts` accepts:
  - `:client-secret` — client secret string
  - `:redirect-uris` — vector of redirect URIs
  - `:token-endpoint-auth-method` — one of `:client-secret-post` (default when secret present), `:client-secret-basic`, or `:none`

### Authorization

- `(build-authorization-url config params)` — Build the authorization endpoint URL. `params` is a map of standard OAuth/OIDC parameters (`:redirect_uri`, `:scope`, `:state`, `:nonce`, `:code_challenge`, `:code_challenge_method`, etc.). Defaults `response_type` to `"code"`.

### Token grants

- `(authorization-code-grant config opts)` — Exchange an authorization code for tokens. `opts` keys: `:code`, `:redirect_uri`, `:code_verifier`.
- `(refresh-token-grant config refresh-token)` — Refresh tokens.
- `(refresh-token-grant config refresh-token extra-params)` — Refresh with additional params (e.g. `{:scope "openid"}`).
- `(client-credentials-grant config)` — Client credentials grant.
- `(client-credentials-grant config extra-params)` — Client credentials with additional params.

### UserInfo

- `(fetch-userinfo config access-token)` — Fetch claims from the UserInfo endpoint.

### Token management

- `(revoke-token config token)` — Revoke a token.
- `(revoke-token config token opts)` — Revoke with `{:token_type_hint "refresh_token"}`.
- `(introspect-token config token)` — Introspect a token. Returns parsed response.
- `(introspect-token config token opts)` — Introspect with `{:token_type_hint "access_token"}`.

### Logout

- `(build-end-session-url config)` — Build an RP-Initiated Logout URL.
- `(build-end-session-url config params)` — With `:id_token_hint`, `:post_logout_redirect_uri`, `:state`.

### Protected resources

- `(fetch-protected-resource access-token url)` — GET a protected resource with a Bearer token.
- `(fetch-protected-resource access-token url opts)` — With `{:method :post}` etc.

### PKCE & random values

- `(random-pkce-code-verifier)` — Generate a random PKCE code verifier.
- `(pkce-code-challenge verifier)` — Compute the S256 code challenge.
- `(random-state)` — Generate a random `state` value.
- `(random-nonce)` — Generate a random `nonce` value.
- `(supports-pkce? server-metadata)` — Check if the server advertises S256 support.

### Utilities

- `(random-bytes n)` — `n` cryptographically random bytes.
- `(base64url-encode bytes)` — Base64url encode (no padding).
- `(base64url-decode string)` — Base64url decode.

## Client authentication methods

The library supports three authentication methods, selected via `:token-endpoint-auth-method` in `configuration`:

| Method | When used |
|---|---|
| `:client-secret-post` | Default when a client secret is provided. Sends `client_id` and `client_secret` in the POST body. |
| `:client-secret-basic` | Sends credentials in the `Authorization: Basic` header. |
| `:none` | Default for public clients (no secret). Sends only `client_id` in the POST body. |

## Development

Start a REPL with dev and test paths:

```sh
clj -M:dev
```

Run tests:

```sh
clj -M:test
```

Tests use ephemeral in-process HTTP servers (`com.sun.net.httpserver.HttpServer`) — no external services required.

## Not yet implemented

The following features from [panva/openid-client](https://github.com/panva/openid-client) are not yet ported:

- DPoP (Demonstration of Proof-of-Possession)
- Device Authorization Grant
- CIBA (Client Initiated Backchannel Authentication)
- PAR (Pushed Authorization Requests)
- JAR (JWT-Secured Authorization Request)
- JARM (JWT-Secured Authorization Response Mode)
- Dynamic Client Registration

## License

EPL-2.0
