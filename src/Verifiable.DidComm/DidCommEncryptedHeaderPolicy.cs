namespace Verifiable.DidComm;

/// <summary>
/// How strictly the DIDComm encrypted-message unpack enforces the common protected headers the spec marks
/// MUST-present — <c>apv</c> (anoncrypt and authcrypt) and <c>apu</c> (authcrypt) — per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#ecdh-es-key-wrapping-and-common-protected-headers">DIDComm Messaging v2.1 §ECDH-ES key wrapping and common protected headers</see>
/// and §ECDH-1PU key wrapping and common protected headers.
/// </summary>
/// <remarks>
/// <para>
/// The spec requires the common protected header to carry <c>apv</c> for every encrypted message and, for
/// authcrypt, <c>apu</c> (which carries <c>base64url(skid)</c>). <see cref="Strict"/> is the
/// spec-compliant default: an envelope missing one of these MUST-present headers is rejected outright as a
/// malformed envelope, so the in-house unpack is a strict conformance oracle that reproduces a conformant
/// peer's rejection rather than silently tolerating a non-conforming sender.
/// </para>
/// <para>
/// <see cref="AllowMissingCommonHeaders"/> relaxes only the <em>presence</em> requirement, for
/// interoperating with a non-conformant peer that omits these headers; it never relaxes a value check. The
/// relaxation is defense-in-depth-safe because the Concat KDF binds <c>apu</c>/<c>apv</c> as the
/// PartyUInfo/PartyVInfo derivation inputs (RFC 7518 §4.6): an envelope that actually omits or tampers with
/// them derives a different key-encryption key than the sender used and fails decryption regardless. The
/// observable difference is only that the lenient policy defers the failure to the cryptographic layer
/// (<see cref="DidCommDecryptionError.DecryptionFailed"/>) instead of rejecting early
/// (<see cref="DidCommDecryptionError.MalformedEnvelope"/>).
/// </para>
/// </remarks>
public enum DidCommEncryptedHeaderPolicy
{
    /// <summary>
    /// Spec-compliant (the default): reject an envelope missing a MUST-present common protected header —
    /// <c>apv</c> for both modes, and <c>apu</c> for authcrypt — as a malformed envelope, before decryption.
    /// </summary>
    Strict = 0,

    /// <summary>
    /// Lenient interop: accept an envelope missing <c>apv</c>/<c>apu</c>, validating each only when present.
    /// Use this ONLY to interoperate with a non-conformant peer that omits these MUST-present headers; the
    /// Concat KDF still binds them, so a genuinely missing or tampered header fails decryption anyway.
    /// </summary>
    AllowMissingCommonHeaders = 1
}
