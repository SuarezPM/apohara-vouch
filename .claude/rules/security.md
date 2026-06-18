# Security — MOIRAI v4

## Mandatory security checks

Before ANY commit:
- [ ] No hardcoded secrets in source (API keys, passwords, tokens, signing keys)
- [ ] All user input validated at the system edge (Band room, HTTP handler)
- [ ] No SQL — we don't have a DB. If a vector store is added, use parameterized queries.
- [ ] No path traversal: validate any file path coming from Band room or HTTP request
- [ ] Signatures verified before trust: every ChainEntry's `signature_hex` is verified against the actor's public key before being appended
- [ ] PRC verification (AC13): every PR Review Certificate's Ed25519 sig + BLAKE3 chain is verifiable offline with `openssl + jq` in <30s
- [ ] EU AI Act Art. 12 fields: ≥7/8 populated (AC15)

## Secret Management

```rust
// NEVER: hardcoded secrets
const FABLE5_KEY_DISABLED: &str = "sk-proj-xxxxx"; // Fable 5 is export-control restricted; using Sonnet 4.5 via AIML API gateway instead

// GOOD: env var with explicit error
let api_key = std::env::var("ANTHROPIC_API_KEY")
    .expect("ANTHROPIC_API_KEY not set; source ~/.config/apohara/secrets.env first");
```

Secrets live in `~/.config/apohara/secrets.env` (chmod 600, outside repo, never committed).

`.env` files are in `.gitignore`. If a `.env` ever appears, **stop and ask Pablo**.

## Injection Defense

We inherit Band's `@mention` routing. The dangerous channel is LLM output. The Compressor (WS5) is the gate:

1. **Lachesis** sees `@Lachesis` only — never raw user input directly
2. **Eris** sees Lachesis's structured findings + repo context — never raw code as a "do this" instruction
3. **Vindex** sees the structured debate output, not raw
4. **Átropos** sees the full chain via `/events`, then emits a structured verdict

The Cordon Principle (arXiv 2605.26754) is built in: **the synthesis agent (Átropos) does NOT see raw evidence**, only the structured findings from the other agents.

## Cryptographic Verification

The PRC is the security boundary. Every agent signs its entries with Ed25519. The chain is BLAKE3-linked. Offline verification (`openssl + jq`) is AC13.

```rust
// Correct: verify the Ed25519 signature before trusting the action
fn verify_chain_entry(entry: &ChainEntry, actor_pubkey: &VerifyingKey) -> bool {
    let sig_bytes = hex::decode(entry.signature_hex.as_deref().unwrap_or(""))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes)?;
    let payload = canonical_json_bytes(entry)?;
    actor_pubkey.verify_strict(&payload, &sig).is_ok()
}
```

## Demo security

The demo URL is public. Promises:
- Agents can read PRs but never `git push` or `git merge`
- The Rust SDK PR is opened by Pablo's GitHub identity (SuarezPM), not the demo URL
- Demo API keys are scoped to read-only operations

## What NOT to do

- **No `unsafe`** in production code without explicit justification, audit, and a `// SAFETY:` comment.
- **No hardcoded URLs** that aren't in `BandClient::new()` config or env vars
- **No MD5, SHA-1, or other broken hash** for security purposes. BLAKE3 for chains, SHA-256 for compat.
- **No mock signing keys** in production — only in tests.
