namespace Verifiable.Fido2;

/// <summary>
/// Encodes a self-attestation <c>packed</c> attestation statement into its CTAP2 canonical CBOR bytes —
/// the authenticator-side counterpart to <see cref="ParsePackedAttestationStatementDelegate"/>'s
/// self-attestation acceptance path.
/// </summary>
/// <param name="alg">The credential private key's COSE algorithm identifier (the CBOR <c>alg</c> member).</param>
/// <param name="signature">
/// The self-attestation signature bytes (the CBOR <c>sig</c> member): a signature over
/// <c>authenticatorData ‖ clientDataHash</c> produced with the credential private key, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3,
/// section 8.2: Packed Attestation Statement Format</see>'s signing procedure.
/// </param>
/// <returns>
/// The encoded, text-keyed <c>attStmt</c> bytes with the <c>x5c</c> member omitted entirely, wrapped in a
/// <see cref="TaggedMemory{T}"/> so the buffer's provenance travels with it without a defensive copy.
/// </returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCredentialPublicKeyDelegate"/>'s own seam shape. The
/// shipped default, <c>Verifiable.Cbor.Fido2.PackedAttestationStatementCborWriter.Write</c>, is
/// method-group-compatible with this delegate. A <c>CtapAuthenticatorSimulator</c> minting a fresh
/// credential composes this seam when it self-attests the newly minted key, mirroring how it already
/// composes <see cref="EncodeCredentialPublicKeyDelegate"/> for the credential's public key.
/// </remarks>
public delegate TaggedMemory<byte> EncodePackedSelfAttestationStatementDelegate(int alg, ReadOnlySpan<byte> signature);
