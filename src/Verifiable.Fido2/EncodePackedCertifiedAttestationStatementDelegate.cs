using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// Encodes a certified <c>packed</c> attestation statement into its CTAP2 canonical CBOR bytes — the
/// authenticator-side counterpart to <see cref="ParsePackedAttestationStatementDelegate"/>'s
/// certified-attestation acceptance path (the <c>x5c</c>-present branch).
/// </summary>
/// <param name="alg">The seeded enterprise attestation private key's COSE algorithm identifier (the CBOR <c>alg</c> member).</param>
/// <param name="signature">
/// The certified attestation signature bytes (the CBOR <c>sig</c> member): a signature over
/// <c>authenticatorData ‖ clientDataHash</c> produced with the SEEDED enterprise attestation private
/// key (CTAP 2.3 §7.1, waveep R7) — never the credential private key, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3,
/// section 8.2: Packed Attestation Statement Format</see>'s signing procedure.
/// </param>
/// <param name="x5c">
/// The seeded attestation certificate chain, leaf-first, as DER-encoded entries (the CBOR <c>x5c</c>
/// member). Opaque to the caller: never parsed, only carried onto the wire verbatim.
/// </param>
/// <returns>
/// The encoded, text-keyed <c>attStmt</c> bytes with <c>alg</c>, <c>sig</c>, and <c>x5c</c> all present,
/// wrapped in a <see cref="TaggedMemory{T}"/> so the buffer's provenance travels with it without a
/// defensive copy.
/// </returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, mirroring
/// <see cref="EncodePackedSelfAttestationStatementDelegate"/>'s own seam shape — keeping
/// <c>Verifiable.Fido2</c> serialization-agnostic. The shipped default,
/// <c>Verifiable.Cbor.Fido2.PackedAttestationStatementCborWriter.WriteCertified</c>, is
/// method-group-compatible with this delegate. A <c>CtapAuthenticatorSimulator</c> minting an
/// enterprise-attested credential composes this seam once mc Step 9 has granted the enterprise
/// attestation (waveep R6), never for a self-attested credential.
/// </remarks>
public delegate TaggedMemory<byte> EncodePackedCertifiedAttestationStatementDelegate(int alg, ReadOnlySpan<byte> signature, IReadOnlyList<PkiCertificateMemory> x5c);
