# FlashProxy Security & Correctness Review

## 1. JWT Implementation (`src/security.rs`)

### Bearer prefix parsing
- **Current:** `auth_val.starts_with("Bearer ")` is **case-sensitive**. RFC 7250 allows clients to send `bearer ` (lowercase); rejecting it can break legitimate clients.
- **Token:** After stripping the prefix you use `auth_val[7..]` with no `.trim()`. A value like `Bearer  \t\n eyJ...` would pass and hand a whitespace-padded token to the decoder. Some libraries tolerate it; trimming is safer and avoids odd edge cases.
- **Recommendation:** Use case-insensitive prefix check and trim the token (see fix below).

### HS256 validation
- **Secure:** You use `DecodingKey::from_secret()` and `Validation::new(Algorithm::HS256)` only, so no algorithm confusion. `jsonwebtoken` validates `exp` by default (`validate_exp: true`).
- **Recommendation:** Set `validation.validate_exp = true` explicitly so the contract is clear and future defaults don’t change behavior.

---

## 2. Rate limiting concurrency

- **Design:** `DashMap<String, Mutex<SlidingWindow>>` is a good fit: sharding is by key (client IP), so different IPs don’t contend. Per-IP serialization is appropriate for a sliding-window counter.
- **Bottleneck:** Only requests from the *same* IP serialize on that IP’s mutex. That’s expected and acceptable for rate limiting.
- **Critical risk:** `entry.lock().expect("lock")` will **panic** if the mutex is poisoned (e.g. a thread panicked while holding the lock). Under load that can take down a worker and cause request failures.
- **Recommendation:** Handle poison by either using the inner data or treating as “allow”/“reject” and log, but never `.expect()` (see fix below).

---

## 3. Metrics accuracy

- **Behavior:** Pingora invokes `logging()` after the request is finished whether you return `Ok(true)` or `Ok(false)` from `request_filter`. So 401/403/429 responses you send via `respond_error()` are still logged and can be recorded.
- **Your flow:** You set `ctx.method` and `ctx.path` at the start of `request_filter` before any early returns. When you `respond_error(401)` and `return Ok(true)`, the response is written and later `logging()` runs with `response_written()` set to 401 and `ctx` already populated. So **401/403/429 are correctly reflected in metrics** as long as `logging()` runs (which it does).
- **Conclusion:** No change required for correctness; the current design is correct.

---

## 4. Error handling – panics in request path

| Location | Risk | Trigger |
|--------|------|--------|
| `proxy.rs:48` | `ResponseHeader::build(200, Some(4)).unwrap()` | Build failure (e.g. API change) → panic. |
| `proxy.rs:49` | `insert_header(...).unwrap()` | Header insert failure → panic. |
| `proxy.rs:46` | `self.metrics.encode()` returns `String`; if `encode()` panics (see below), this propagates. | Handled by fixing `metrics.encode()`. |
| `metrics.rs:48` | `encoder.encode(...).unwrap()` | Encode error (e.g. invalid metric) → panic on `/metrics`. |
| `metrics.rs:49` | `String::from_utf8(buffer).unwrap()` | Non-UTF-8 from encoder → panic on `/metrics`. |
| `security.rs:50` | `entry.lock().expect("lock")` | Poisoned mutex → panic. |

Startup-only unwraps in `main.rs` (config, server, TLS) are acceptable; they fail fast at boot. The ones above are in the **request path** and should be hardened so a malformed or abusive request cannot crash the process.

---

## Summary of fixes applied (in code)

1. **security.rs:** JWT – case-insensitive “Bearer ” prefix, trim token, explicit `validate_exp`; rate limiter – handle poisoned mutex with `into_inner()` instead of `.expect("lock")`.
2. **proxy.rs:** Replaced all `unwrap()` in the `/metrics` path: `metrics.encode()` returns `Result`, `ResponseHeader::build` and `insert_header` use `.map_err(...)?` so failures become 500 instead of panic.
3. **metrics.rs:** `encode()` now returns `Result<String, prometheus::Error>`; encoder and UTF-8 errors are propagated instead of panicking.
