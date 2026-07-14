using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The inputs to an attestation statement format's verification procedure.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats">W3C Web Authentication Level 3, section 8: Defined Attestation Statement Formats.</see>
/// Every defined verification procedure takes the same three logical inputs — <c>attStmt</c>,
/// <c>authenticatorData</c>, and <c>clientDataHash</c> — plus, for a certified attestation, the
/// trust anchors and validation time a chain-validation seam needs. This type carries all of
/// them so a single <see cref="AttestationVerifyDelegate"/> signature serves every format.
/// <para>
/// <strong>Ownership.</strong> This request only references caller-owned carriers; it does not
/// take ownership of <see cref="AuthenticatorDataBytes"/>, <see cref="ClientDataHash"/>,
/// <see cref="AttestationStatement"/>, or <see cref="TrustAnchors"/>, and does not dispose them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AttestationVerificationRequest
{
    /// <summary>
    /// Initializes an <see cref="AttestationVerificationRequest"/> from its verification inputs.
    /// </summary>
    /// <param name="authenticatorDataBytes">The raw <c>authData</c> bytes, per <see cref="AuthenticatorDataBytes"/>.</param>
    /// <param name="authenticatorData">The parsed authenticator data view, per <see cref="AuthenticatorData"/>.</param>
    /// <param name="clientDataHash">The client data hash, per <see cref="ClientDataHash"/>.</param>
    /// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes, per <see cref="AttestationStatement"/>.</param>
    /// <param name="trustAnchors">The trust anchor certificates, per <see cref="TrustAnchors"/>.</param>
    /// <param name="validationTime">The time at which to evaluate certificate validity, per <see cref="ValidationTime"/>.</param>
    /// <param name="pool">The memory pool, per <see cref="Pool"/>.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="authenticatorData"/>, <paramref name="clientDataHash"/>,
    /// <paramref name="trustAnchors"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    public AttestationVerificationRequest(
        ReadOnlyMemory<byte> authenticatorDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash,
        ReadOnlyMemory<byte> attestationStatement,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);

        AuthenticatorDataBytes = authenticatorDataBytes;
        AuthenticatorData = authenticatorData;
        ClientDataHash = clientDataHash;
        AttestationStatement = attestationStatement;
        TrustAnchors = trustAnchors;
        ValidationTime = validationTime;
        Pool = pool;
    }


    /// <summary>
    /// The raw <c>authData</c> bytes. The attestation signature covers these exact bytes, not a
    /// re-serialization of the parsed view, so this is what a verification procedure signs over
    /// — see <see cref="AuthenticatorData"/> for the parsed view aliasing the same buffer.
    /// </summary>
    public ReadOnlyMemory<byte> AuthenticatorDataBytes { get; }

    /// <summary>
    /// The parsed <c>authData</c> view, aliasing <see cref="AuthenticatorDataBytes"/> — for
    /// reading fields such as the attested credential data's AAGUID and credential public key.
    /// </summary>
    public AuthenticatorData AuthenticatorData { get; }

    /// <summary>
    /// The hash of the serialized client data (<c>clientDataHash</c>), the second component the
    /// attestation signature covers alongside <see cref="AuthenticatorDataBytes"/>.
    /// </summary>
    public DigestValue ClientDataHash { get; }

    /// <summary>
    /// The raw <c>attStmt</c> CBOR bytes, opaque at this layer — decoded by the format-specific
    /// <see cref="AttestationVerifyDelegate"/> registered for the statement's <c>fmt</c>.
    /// </summary>
    public ReadOnlyMemory<byte> AttestationStatement { get; }

    /// <summary>
    /// The trust anchor certificates against which a certified attestation's certificate path is
    /// validated. May be empty when no trust anchors are configured for the attestation type and
    /// format, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 23.
    /// </summary>
    public IReadOnlyList<PkiCertificateMemory> TrustAnchors { get; }

    /// <summary>
    /// Whether the registration ceremony that produced this attestation requested enterprise
    /// attestation (<c>attestation: "enterprise"</c>), permitting a packed attestation
    /// certificate to carry the enterprise attestation serial-number extension. Defaults to
    /// <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements">W3C
    /// Web Authentication Level 3, section 8.2.2: Certificate Requirements for Enterprise Packed
    /// Attestation Statements.</see> "This extension MUST NOT be present in non-enterprise
    /// attestations." This codebase has no registration-options builder yet — the CR's own
    /// client-computed <c>enterpriseAttestationPossible</c> flag (section 5.1.3) is unmodeled
    /// here — so a caller whose own options conveyed <c>attestation: "enterprise"</c> sets this
    /// to <see langword="true"/> to thread that fact through to the packed format's section
    /// 8.2.2 check; see <see cref="Fido2AttestationErrors.SerialNumberExtensionNotPermitted"/>.
    /// </remarks>
    public bool AcceptsEnterpriseAttestation { get; init; }

    /// <summary>
    /// Whether the relying party's downgrade policy accepts a certified attestation whose trust
    /// path did not reach a supplied anchor as equivalent to <c>none</c> attestation. Defaults to
    /// <see langword="false"/> — today's fail-closed rejection.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, the ceremony's
    /// final step: "The Relying Party MAY consider the credential as equivalent to one with no
    /// attestation" (see <see href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">section
    /// 6.5.3: Attestation Types</see>). This value is not itself consulted by any per-format
    /// verification procedure — no defined attestation format's own algorithm references it, unlike
    /// <see cref="AcceptsEnterpriseAttestation"/>'s section 8.2.2 certificate-profile check — it is
    /// carried on the request purely so <see cref="Fido2RegistrationVerifier"/>, the orchestrator
    /// that resolves the final <see cref="AttestationResult"/>, has it available at the point it
    /// decides whether a <see cref="RejectedAttestationResult"/> carrying
    /// <see cref="Fido2AttestationErrors.NoTrustAnchors"/> or
    /// <see cref="Fido2AttestationErrors.ChainValidationFailed"/> should be replaced with a
    /// <see cref="NoneAttestationResult"/>. A rejection for any other reason — an invalid signature,
    /// a malformed statement, or any other structural failure — is never downgraded regardless of
    /// this value.
    /// </remarks>
    public bool AcceptsUntrustedAttestationAsNone { get; init; }

    /// <summary>
    /// The UTC time at which to evaluate certificate validity during chain validation.
    /// </summary>
    public DateTimeOffset ValidationTime { get; }

    /// <summary>
    /// The memory pool a verification procedure allocates working buffers from — for example the
    /// concatenation of <see cref="AuthenticatorDataBytes"/> and <see cref="ClientDataHash"/>, or
    /// key material converted from a COSE_Key.
    /// </summary>
    public MemoryPool<byte> Pool { get; }


    /// <summary>
    /// A debugger-friendly summary of the request's size and trust-anchor count, rather than
    /// every field, matching this codebase's convention for non-owning input bags.
    /// </summary>
    private string DebuggerDisplay => $"AttestationVerificationRequest({AuthenticatorDataBytes.Length} bytes authData, TrustAnchors={TrustAnchors.Count})";
}
