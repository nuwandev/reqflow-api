# 0. PROJECT IMPLEMENTATION INVENTORY
Runtime and build
- Entry point: `ReqflowApiApplication` (`src/main/java/com/nuwandev/reqflowapi/ReqflowApiApplication.java`).
- Java 21 with Spring Boot 4.0.5 (`pom.xml`).
- Key deps: `spring-boot-starter-web`, `spring-boot-starter-security`, `spring-boot-starter-validation`, `spring-boot-starter-actuator`, `spring-boot-starter-flyway`, `flyway-database-postgresql`, `postgresql`, `nimbus-jose-jwt`.
- No test sources or test dependencies present.

Configuration and runtime inputs
- Config file: `src/main/resources/application.yaml`.
- Environment import: `spring.config.import: file:.env[.properties]` (local dotenv pattern).
- Datasource: `${DB_URI}`, `${DB_USERNAME}`, `${DB_PASSWORD}` with Postgres driver.
- Auth settings: `AUTH_ACCESS_TOKEN_TTL_SECONDS`, `AUTH_REFRESH_TOKEN_TTL_SECONDS`, `AUTH_JWT_CLOCK_SKEW_SECONDS`, `AUTH_JWT_ISSUER`, `AUTH_JWT_SECRET`.
- Rate limit settings: `AUTH_RATE_LIMIT_LOGIN_PER_WINDOW`, `AUTH_RATE_LIMIT_REFRESH_PER_WINDOW`, `AUTH_RATE_LIMIT_WINDOW_SECONDS`.
- Virtual threads enabled: `spring.threads.virtual.enabled: true`.

HTTP API surface (current controllers)
- `AuthController` (`/api/v1/auth`) provides:
  - `POST /login`: accepts `LoginRequest` (`tenantId`, `email`, `password`); sets `reqflow_refresh` cookie; returns `AuthTokenResponse` (access token only).
  - `POST /refresh`: reads `reqflow_refresh` cookie; sets new cookie; returns `AuthTokenResponse`.
  - `POST /logout`: requires auth; revokes sessions; clears refresh cookie; returns 204.
  - `GET /me`: requires auth; returns `MeResponse` with `userId`, `tenantId`, `role`.
- `SecurityConfiguration` only permits `/api/v1/auth/login`, `/api/v1/auth/refresh`, and `/actuator/health` anonymously; everything else is denied.

Response envelopes and error handling
- Success responses are wrapped by `ApiResponseAdvice` into `SuccessEnvelope { data, meta }` unless the body is already an envelope.
- `Meta` includes `traceId` and `timestamp` (ISO-8601).
- Validation errors and domain auth exceptions are converted by `GlobalExceptionHandler` into `ErrorEnvelope` with `errorCode`, `message`, optional `details`, `traceId`, and `timestamp`.
- Security auth failures bypass the envelope and return raw JSON via `JsonAuthenticationEntryPoint` (`{"error":"unauthorized"}`) and `JsonAccessDeniedHandler` (`{"error":"forbidden"}`).
- `TraceIdFilter` reads/writes `X-Trace-Id`, sets request attribute and MDC key `traceId`.

Security filter chain and auth mechanics
- Stateless security: CSRF disabled, HTTP basic/form login disabled, `SessionCreationPolicy.STATELESS`.
- Filters: `AuthRateLimitFilter` and `BearerTokenAuthenticationFilter` are inserted before `UsernamePasswordAuthenticationFilter`.
- `AuthRateLimitFilter` is in-memory (per-instance) IP-based throttling for `/api/v1/auth/login` and `/api/v1/auth/refresh` only.
- `BearerTokenAuthenticationFilter` validates JWTs via `JwtPort`, then sets `AuthenticatedUser` + authority `ROLE_<ROLE>`.
- `HmacJwtService` is the sole JWT implementation (HS256, fixed audience `reqflow-api`, issuer from config, clock skew configured).
- `SecurityContextAuthContext` reads `AuthenticatedUser` from the `SecurityContextHolder`.

Domain and application layering
- Presentation: REST controller + DTOs under `identity/presentation/rest`.
- Application services: `LoginService`, `RefreshTokenService`, `LogoutService` orchestrate flow via ports.
- Domain: `User`, `AuthSession`, `UserRole` with invariants; domain exceptions for auth flows.
- Ports:
  - Input ports (`LoginUseCase`, `RefreshTokenUseCase`, `LogoutUseCase`) are direct interfaces for services.
  - Output ports (`JwtPort`, `PasswordHasherPort`, `RefreshTokenGenerator`, `TokenHasher`, `AuthContext`) wrap infra concerns.

Persistence and data access
- JDBC-based repositories (`JdbcUserRepository`, `JdbcAuthSessionRepository`) with `JdbcTemplate`.
- Entity objects for persistence (`UserEntity`, `AuthSessionEntity`), mapped via `UserMapper` and `AuthSessionMapper`.
- Repositories support lookup by tenant+email/userId and refresh token hash (FOR UPDATE), and session revocation by user.

Database schema (Flyway)
- `tenants` table with unique `slug`, `is_active`, timestamps.
- `teams` table with `tenant_id` FK, unique `(tenant_id, name)`, indexes on `tenant_id`.
- `users` table with `tenant_id` FK, unique `(tenant_id, email)`, `role` enum check, optional `team_id` FK, indexes on `(tenant_id, role)` and `(tenant_id, team_id)`.
- `auth_sessions` table with `tenant_id` FK, `user_id` FK, `refresh_token_hash`, `replaced_by_session_id` self-FK, and indexes on `(tenant_id, user_id, expires_at)`, `(tenant_id, refresh_token_hash, expires_at)` for active sessions, and `(tenant_id, user_id, revoked_at)`.

Local infrastructure
- `compose.yaml` provides Postgres 18 container with env-driven credentials and a named volume.

# 1. CURRENT SYSTEM OVERVIEW
Login (end-to-end)
- Entry point: `AuthController.login` (`src/main/java/com/nuwandev/reqflowapi/identity/presentation/rest/AuthController.java`).
- Input: `LoginRequest` requires `tenantId`, `email`, `password` (`src/main/java/com/nuwandev/reqflowapi/identity/presentation/rest/dto/LoginRequest.java`).
- Flow: controller builds `LoginCommand` with tenantId + credentials + request IP/User-Agent, calls `LoginService.execute`.
- `LoginService` (`src/main/java/com/nuwandev/reqflowapi/identity/application/service/LoginService.java`) loads user by `(tenantId, email)` via `UserRepository.findByEmail`, verifies `isActive`, checks BCrypt password, creates an `AuthSession`, persists it, then returns access token + raw refresh token.
- Response: access token returned in JSON (`AuthTokenResponse`); refresh token is set as `reqflow_refresh` cookie, HttpOnly + Secure + SameSite=Lax, Path `/api/v1/auth`.

Refresh (end-to-end)
- Entry point: `AuthController.refresh` reads `reqflow_refresh` cookie; missing cookie throws `IllegalArgumentException` => 400.
- `RefreshTokenService` hashes incoming refresh token and looks up session by hash with `FOR UPDATE` (`AuthSessionRepository.findByRefreshTokenHashForUpdate`).
- If session expired/revoked/replaced, refresh fails; if revoked+replaced, chain is revoked (`revokeSessionChain`) and `RefreshTokenReuseDetectedException` => 401.
- If user inactive, all sessions revoked, 403.
- On success, a new session is created, previous session rotated (revoked + replaced_by), new refresh token returned in cookie, new access token in body.

Logout (end-to-end)
- Entry point: `AuthController.logout` (authenticated) calls `LogoutService.execute` with tenantId/userId from `AuthContext`.
- `LogoutService` revokes all sessions for user in tenant (DB update); response clears refresh cookie (Max-Age=0).
- Access tokens are NOT revoked; they remain valid until expiry.

Request authentication
- `BearerTokenAuthenticationFilter` reads `Authorization: Bearer <token>` and calls `JwtPort.parseAndValidate`.
- On success, it builds a `UsernamePasswordAuthenticationToken` with principal = `AuthenticatedUser` and authority `ROLE_<ROLE>`.
- The authentication is stored in `SecurityContextHolder`; downstream controllers read it via `AuthContext`.

SecurityContext
- `SecurityContextAuthContext` uses `SecurityContextHolder.getContext().getAuthentication()` and expects `AuthenticatedUser` as principal.
- `AuthContext.currentUser()` throws if unauthenticated; `/me` and `/logout` call this directly.

JWT claims flow
- `HmacJwtService.generateAccessToken` builds claims: `sub` (userId), `tenantId`, `role`, `iss`, `aud`, `iat`, `nbf`, `exp`.
- `aud` is hard-coded to `reqflow-api` (not configurable); `iss` is configurable via `auth.jwt.issuer`.
- `parseAndValidate` verifies HS256 signature, issuer, audience, exp/nbf, then builds `AuthenticatedUser` from `sub`, `tenantId`, `role`.

Access token lifecycle
- Minted at login or refresh using `HmacJwtService.generateAccessToken` and the current `Clock`.
- Validated per request by `BearerTokenAuthenticationFilter`; no DB lookup or revocation check.
- Expires strictly by `exp` + clock skew; logout does not invalidate access tokens.

Refresh token lifecycle
- Minted at login or refresh by `SecureRefreshTokenGenerator` (32 random bytes, URL-safe Base64).
- Stored only as a SHA-256 hash in `auth_sessions.refresh_token_hash` via `Sha256TokenHasher`.
- Rotated on refresh: old session is revoked and linked to the new session (`replaced_by_session_id`).
- Reuse detection: if a revoked+replaced session is used again, the chain is revoked and the request fails with 401.
- Revoked on logout (`revokeAllByUserId`) and when user becomes inactive (during refresh).

Auth session lifecycle
- Created on login or refresh as a new `AuthSession` with `issued_at`, `expires_at`, and optional `ip_address`/`user_agent`.
- Rotated on refresh: old session revoked and linked to replacement; new session created with new token hash.
- Revoked on logout or on user deactivation during refresh.
- No scheduled cleanup; expired rows remain indefinitely.

Tenant isolation
- Tenant isolation is enforced in `UserRepository` queries (tenant_id in WHERE), and in `AuthSessionRepository.findById` + `revokeAllByUserId`.
- Refresh lookup uses only `refresh_token_hash` without `tenant_id` filter; tenant isolation relies on token secrecy, not DB enforcement.

Trust boundaries
- External boundary: HTTP requests in `AuthController` and `BearerTokenAuthenticationFilter`.
- Internal trust: after JWT validation, the entire request trusts the `AuthenticatedUser` from token with no DB re-check.
- Refresh boundary: a valid refresh token is sufficient to mint a new access token without re-authentication.

Central objects
- `AuthSession` is the core refresh-rotation entity.
- `AuthenticatedUser` is the in-request identity snapshot.
- `HmacJwtService` is the only JWT implementation.
- `AuthContext` is the adapter for current principal access.
- `AuthTokens` is the application-level return type for access + refresh tokens.

# 2. SPRING SECURITY EXPLANATION
What SecurityContextHolder is
- It is a thread-bound holder (via `SecurityContextHolder`) that stores the current `SecurityContext` for the request.
- The `SecurityContext` holds the `Authentication` object, which represents the current principal and their authorities.

Who populates it
- In this system, `BearerTokenAuthenticationFilter` populates it after validating the JWT.
- If the token is invalid, it delegates to `JsonAuthenticationEntryPoint` which returns 401 with a minimal JSON body.
- If the token is missing, the request proceeds unauthenticated and may be denied later by route rules.

How filters work
- Spring Security composes a filter chain; each filter can read/modify the request or security context.
- `OncePerRequestFilter` runs once per request. Your custom filters (`AuthRateLimitFilter`, `BearerTokenAuthenticationFilter`) run before `UsernamePasswordAuthenticationFilter`.
- With stateless config, no HTTP session is created; the `SecurityContext` lives only for the request.

SecurityContext lifecycle (per request)
- Created empty at the start of the request.
- Populated by `BearerTokenAuthenticationFilter` if the JWT is valid.
- Read by `SecurityContextAuthContext` in controllers/services.
- Cleared automatically at the end of the request (thread-local lifecycle).

How the Bearer token becomes an authenticated principal
- `BearerTokenAuthenticationFilter` parses `Authorization` header, validates JWT, and then creates `UsernamePasswordAuthenticationToken.authenticated(...)`.
- The principal is `AuthenticatedUser`, and a single authority `ROLE_<ROLE>` is added.

How @PreAuthorize works internally
- `@PreAuthorize` uses Spring AOP + method security interceptors.
- The interceptor evaluates the SpEL expression before method execution.
- If the expression evaluates to false, access is denied before method body runs.

What SpEL is
- Spring Expression Language (SpEL) lets you reference beans, method params, and static types inside annotations.
- Example here: `@authz.hasRole(...)` or `@authz.isCurrentUser(#userId)`.

How authorities/roles work
- Authorities are simple strings (like `ROLE_ADMIN`) stored on the `Authentication` object.
- Spring treats anything with the `ROLE_` prefix as a role; `hasRole('ADMIN')` maps to authority `ROLE_ADMIN`.

Authentication vs authorization
- Authentication answers "who are you" (valid JWT -> `AuthenticatedUser`).
- Authorization answers "are you allowed" (e.g., role checks or tenant checks in `@PreAuthorize`).

Where current user info lives during request lifecycle
- It lives in `SecurityContextHolder.getContext().getAuthentication().getPrincipal()`.
- Your `AuthContext` adapter reads it and exposes `currentUserId`, `currentTenantId`, and `currentRole`.

How stateless auth actually works
- The server does not store access token state; it only verifies signatures and claims on each request.
- Logout only affects refresh tokens; access tokens remain valid until they expire.

# 3. ARCHITECTURE REVIEW
Is the architecture actually clean?
- The package layout matches a clean-ish layering: `presentation`, `application`, `domain`, `infrastructure`.
- As “hexagonal architecture,” it is partial: input ports exist but only the REST controller uses them, and no alternate adapters exist; output ports are meaningful seams (JWT, hashing, token generation).
- Application services are thin and mostly orchestration (good), domain models contain some behavior (moderate, not fully anemic).

Fake abstractions / overengineering
- Input ports (`LoginUseCase`, `RefreshTokenUseCase`, `LogoutUseCase`) add little value because there are no alternate adapters; they are pure pass-through contracts.
- Output ports (`JwtPort`, `PasswordHasherPort`, `RefreshTokenGenerator`, `TokenHasher`) are more justifiable because they isolate crypto/infra concerns.

Misplaced responsibilities
- `AuthController` constructs cookie headers manually; not wrong, but mixes auth logic with HTTP concerns.
- `AuthRateLimitFilter` is infrastructure, but its logic has production impact and should be driven by a proper rate-limit adapter; current implementation is in-memory and not production-viable.

Use-case pattern justification
- Right now, use-case interfaces are mostly ceremony since only one implementation exists and there is no testing that mocks them.
- If you want to keep a minimal clean architecture, keep the services but remove input interfaces unless you need them for alternate adapters or tests.

Domain layer behavior
- `AuthSession` has behavior (rotate, revoke, canBeUsedForRefresh) and protects invariants. This is a real domain object.
- `User` has basic behavior, but is mostly a data container; still acceptable for now.

Packages to merge/simplify
- Consider merging `application/port/input` interfaces into services if you are not using them as boundaries.
- Keep `application/port/output` because they are genuine seams for JWT, hashing, and token generation.

Files that should be deleted (based on usage)
- `CurrentUserOrAdmin`, `RequiresAdmin`, `TenantAccess` are unused and create a false sense of authorization coverage.
- `AuthorizationGuard` is currently unused and only serves those unused annotations.
- `TokenHasher.verify` is unused; either use it or remove it to avoid dead code.

# 4. SECURITY REVIEW
JWT implementation
- Uses HS256 via `nimbus-jose-jwt` with symmetric secret (`HmacJwtService`).
- Validates algorithm, signature, issuer, audience, exp/nbf. This is correct and minimal.
- `aud` is hard-coded to `reqflow-api` (not an environment-configured audience).
- No `jti` claim, no token revocation list, no key rotation strategy.

Signing algorithm
- HS256 is acceptable for MVP if secret is strong and securely stored.
- Configuration enforces a minimum of 32 bytes, which is good.

Token validation
- Good baseline validation: issuer, audience, exp, nbf.
- No validation that user is still active on each request; deactivated users keep access until access token expires.

Refresh token rotation
- Implements one-time-use refresh tokens with rotation and chain revocation on reuse.
- Refresh token hash stored in DB; raw refresh token never stored (good).
- Refresh tokens are 32 bytes from `SecureRandom`, encoded as URL-safe Base64 (sufficient entropy for bearer tokens).

Replay/reuse detection
- Reuse detection exists (`RefreshTokenReuseDetectedException`) and chain revocation is implemented.
- If the same refresh token is used again, the entire chain is revoked (good).

Brute force protection
- `AuthRateLimitFilter` provides basic IP-based throttling, but it is in-memory and easy to bypass with spoofed `X-Forwarded-For`.
- The filter does not emit `Retry-After` or centralized telemetry, and it only targets `/login` and `/refresh` POSTs.

Session lifecycle
- Session is DB-backed, with revoked/rotated/expired semantics.
- Sessions are rotated with a `replaced_by_session_id` link; reuse is detected by “revoked + replaced” state.
- No cleanup job for expired sessions; DB will grow indefinitely.

Logout semantics
- Logout revokes all refresh sessions for user in tenant, but does NOT revoke access tokens (stateless JWT).
- This is normal for stateless JWT, but it means logout is not immediate for access token usage.

Tenant isolation safety
- User queries are tenant-scoped.
- Refresh token lookup is not tenant-scoped and relies on refresh token entropy. The DB indexes and constraints do not enforce uniqueness per tenant.
- Risk: if refresh token hash collision ever happens (rare but possible) the system could refresh into the wrong tenant.

Privilege escalation risks
- Authorities are derived entirely from JWT claim `role` and are not verified against DB per request.
- If the JWT secret is ever leaked, all tenant boundaries are compromised.

Stateless auth weaknesses
- No access token revocation, no token binding to device or IP.
- Deactivated users continue until token expiry.

Access token revocation strategy
- None implemented. This is a known trade-off, but you should state this explicitly in system design.

Production readiness level (security)
- Good baseline crypto and rotation, but several real risks remain: in-memory rate limiting, no key rotation, no access token revocation, no per-request user status check, and refresh lookup not tenant-scoped.

Critical vulnerabilities
- In-memory rate limiting + trusting `X-Forwarded-For` lets attackers bypass throttling and brute-force credentials at scale.
- Refresh token lookup without tenant scope and without uniqueness constraint can result in cross-tenant token ambiguity if a hash collision or duplication occurs (low probability, high impact).

Architectural security flaws
- Authorization annotations and guard exist but are unused, giving a false impression of role/tenant enforcement beyond `/me` and `/logout`.

Misleading security assumptions
- Logout does not invalidate access tokens; any systems expecting immediate revocation will be wrong.
- Current user authorization is not enforced anywhere except HTTP route-level checks.

# 5. CLEANUP REVIEW
Dead code / unused abstractions
- `src/main/java/com/nuwandev/reqflowapi/identity/infrastructure/security/AuthorizationGuard.java`: unused; only referenced by unused annotations.
- `src/main/java/com/nuwandev/reqflowapi/identity/infrastructure/security/RequiresAdmin.java`: unused.
- `src/main/java/com/nuwandev/reqflowapi/identity/infrastructure/security/CurrentUserOrAdmin.java`: unused.
- `src/main/java/com/nuwandev/reqflowapi/identity/infrastructure/security/TenantAccess.java`: unused.
- `src/main/java/com/nuwandev/reqflowapi/identity/application/port/output/TokenHasher.java#verify`: unused method.

Duplicate / unnecessary layers
- `application/port/input` interfaces are currently thin wrappers without alternate adapters; consider removing them or add tests that mock them.

Unused dependencies
- No explicit unused dependency found from the inspected code; however there are no tests or test dependencies at all.

Bad naming
- Generally consistent and clear. `AuthRateLimitFilter` is accurate but hides the fact that it is in-memory only; consider renaming if kept.

Files that should stay
- Core services: `LoginService`, `RefreshTokenService`, `LogoutService`.
- JWT and crypto adapters: `HmacJwtService`, `BcryptPasswordHasher`, `SecureRefreshTokenGenerator`.
- Domain models: `AuthSession`, `User`.
- JDBC repositories and mappers: required for current data access.

# 6. INDUSTRY ALIGNMENT
Modern Spring Security practices
- Using a custom `OncePerRequestFilter` for JWT is common and acceptable for a minimal setup.
- Missing: `BearerTokenAuthenticationFilter` could be replaced by Spring’s resource server support for JWT, but your custom approach is fine if maintained carefully.
- Tradeoff: custom filters + custom JSON handlers give full control, but increase security maintenance burden versus a standard resource server setup.

Real SaaS authentication systems
- Typical SaaS systems include refresh rotation (you have), session revocation (you have), device/session listing (you do not), and access token revocation or short TTL with re-auth (not implemented).
- Rate limiting in production is usually centralized (Redis, API gateway), not in-memory per instance.

OAuth-inspired patterns
- You are implementing a simplified refresh-rotation flow similar to OAuth2, but without grant types or client separation.
- No client/app identification exists, which is acceptable for internal first-party apps.

Stateless JWT architectures
- Access tokens remain valid until expiry; logout is best-effort by revoking refresh tokens. This matches common stateless designs.
- Missing: key rotation, token versioning, or jti-based denylist if you need immediate revocation.

Production backend standards
- Good: JWT validation, refresh rotation, BCrypt, explicit tenant scoping in user queries.
- Junior-level: in-memory rate limit, unused authorization annotations, no tests, no centralized audit/logging of auth events.
- Fake enterprise complexity: thin input ports that add little value without tests or alternate adapters.
- Likely to fail at scale: in-memory rate limiting, lack of distributed session checks, no cleanup of expired sessions.
- Would impress experienced engineers: clean refresh rotation flow with chain revocation, clear JWT claim handling, JDBC data access without ORM overhead.

# 7. MISSING FEATURES FOR MVP
MUST HAVE before moving forward
- Distributed rate limiting or gateway-based throttling for login/refresh.
- Enforce tenant scoping on refresh lookup (include `tenant_id` in lookup or add uniqueness constraint to prevent ambiguity).
- Basic automated tests for login/refresh/logout flows (even minimal integration tests).

SHOULD HAVE later
- Access token revocation strategy or very short access token TTL with sliding refresh.
- Session cleanup job for expired/revoked sessions.
- Audit logging for auth events (login success/failure, refresh reuse detected, logout).

OPTIONAL future improvements
- Device/session listing endpoint and selective logout.
- Key rotation support for JWT (kid + multiple keys).
- Optional IP/User-Agent binding checks for refresh tokens.

# 8. WHAT SHOULD BE DONE NEXT (STRICT ORDER)
1) Delete unused authorization annotations and guard (`AuthorizationGuard`, `RequiresAdmin`, `CurrentUserOrAdmin`, `TenantAccess`) OR wire them into real endpoints immediately. Do not leave them unused.
2) Fix refresh lookup isolation: scope refresh token lookup by tenant or add a uniqueness guarantee that prevents multi-tenant collision; update DB constraints if needed.
3) Replace in-memory rate limiting with a centralized mechanism (gateway or shared store). Keep the filter shape, replace the backend.
4) Add minimal automated tests for login/refresh/logout and refresh-reuse detection. These are the core security flows.
5) Decide and document access token revocation semantics (accept stateless TTL or add a denylist).
6) Add a periodic cleanup for expired auth sessions.
7) Optional: simplify input port interfaces if they remain unused after tests are in place.

FINAL VERDICT
- Salvageable: Yes. The core flow (JWT + refresh rotation + session model) is solid and not fundamentally broken.
- Strongest parts: Refresh rotation with reuse detection, clean JWT claim handling, clear JDBC repositories.
- Dangerous parts: In-memory rate limiting with spoofable `X-Forwarded-For`, missing tenant scoping on refresh lookup, and no tests.
- Production readiness confidence: 5/10. Good core logic, but needs specific fixes before a real SaaS launch.
