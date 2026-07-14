using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Encodes a COSE_Key <c>credentialPublicKey</c> into its CTAP2 canonical CBOR bytes — the production
/// counterpart to <see cref="ReadCredentialPublicKeyDelegate"/>.
/// </summary>
/// <param name="coseKey">The parsed COSE_Key view to encode.</param>
/// <returns>
/// The encoded COSE_Key bytes, wrapped in a <see cref="TaggedMemory{T}"/> so the buffer's provenance
/// travels with it without a defensive copy.
/// </returns>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication
/// Level 3, section 6.5.1: Attested Credential Data</see>: "credentialPublicKey ... The credential public
/// key encoded in COSE_Key format ... using the CTAP2 canonical CBOR encoding form."
/// </para>
/// <para>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="ReadCredentialPublicKeyDelegate"/>'s own seam shape. The
/// shipped default, <c>Verifiable.Cbor.Fido2.CredentialPublicKeyCborWriter.Write</c>, is
/// method-group-compatible with this delegate. A <c>CtapAuthenticatorSimulator</c> minting a fresh
/// credential composes this seam to turn the freshly generated public key into the opaque
/// <c>credentialPublicKey</c> bytes <c>AuthenticatorDataWriter</c> embeds verbatim.
/// </para>
/// </remarks>
public delegate TaggedMemory<byte> EncodeCredentialPublicKeyDelegate(CoseKey coseKey);
