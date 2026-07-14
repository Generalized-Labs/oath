# Oath contract signatures

Oath decision contracts use Ed25519 over `oath-json-v1` bytes. The detached
signature object carries the base64 public key, base64 signature, algorithm,
and canonicalization version needed to reject unknown encodings.

To verify an `ExecAssessment v3`, `PublishAssessment v2`, or
`RegistryVerdict v1`:

1. Validate the complete document against its published JSON Schema.
2. Retain the detached signature, then set the document's `signature` property
   to JSON `null`.
3. Encode the document as compact UTF-8 JSON. At every object depth, order keys
   lexicographically by Unicode scalar value. Preserve array order. Use normal
   JSON string escaping and base-10 JSON integer encoding; these contracts do
   not contain floating-point numbers.
4. Base64-decode `public_key` to exactly 32 bytes and `signature` to exactly 64
   bytes, then verify Ed25519 over the canonical bytes.

Signed tombstone and checkpoint bundles apply the same encoding directly to
their `payload` object. Evidence and policy digests are lowercase SHA-256 over
the same canonical bytes and include the `sha256:` prefix.

Unknown schema versions, signature algorithms, or canonicalization versions
must fail closed. A valid signature proves integrity under the included key; it
proves signer identity only when that public key is anchored through a trusted
release, registry, organization, or policy channel.
