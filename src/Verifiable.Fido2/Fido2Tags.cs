using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Fido2;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for FIDO2/WebAuthn-specific <see cref="SensitiveMemory"/> subtypes.
/// </summary>
/// <remarks>
/// Mirrors the per-subsystem tag classes elsewhere in this codebase (for example <c>ApduTags</c> and
/// <c>TpmTags</c>): each tag identifies the semantic role of a piece of memory within the FIDO2
/// subsystem, distinct from the generic cryptographic-material tags in <see cref="CryptoTags"/>.
/// </remarks>
public static class Fido2Tags
{
    /// <summary>
    /// Tag for a WebAuthn credential identifier
    /// (<see href="https://www.w3.org/TR/webauthn-3/#credential-id">W3C Web Authentication Level 3,
    /// section 4: Terminology, "Credential ID"</see>).
    /// </summary>
    /// <remarks>
    /// A credential ID is an opaque byte string with no cryptographic structure of its own — the
    /// authenticator mints it and the relying party treats it as an identifier, never as key
    /// material, a digest, or a signature. It therefore carries <see cref="Purpose.Data"/> rather
    /// than any of the key/signature/digest purposes <see cref="CryptoTags"/> defines, with raw
    /// encoding.
    /// </remarks>
    public static Tag CredentialId { get; } = Tag.Create(Purpose.Data).With(EncodingScheme.Raw);

    /// <summary>
    /// Tag for a WebAuthn user handle
    /// (<see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">W3C Web
    /// Authentication Level 3, section 5.4.3: User Account Parameters for Credential Generation
    /// (dictionary <c>PublicKeyCredentialUserEntity</c>)</see>, member <c>id</c>).
    /// </summary>
    /// <remarks>
    /// A user handle is an opaque byte string the relying party assigns and treats as an account
    /// identifier — it carries no cryptographic structure of its own, so it takes
    /// <see cref="Purpose.Data"/> rather than any of the key/signature/digest purposes
    /// <see cref="CryptoTags"/> defines, with raw encoding, mirroring <see cref="CredentialId"/>.
    /// </remarks>
    public static Tag UserHandle { get; } = Tag.Create(Purpose.Data).With(EncodingScheme.Raw);

    /// <summary>
    /// Tag for a WebAuthn cryptographic challenge
    /// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">W3C Web
    /// Authentication Level 3, section 13.4.3: Cryptographic Challenges</see>).
    /// </summary>
    /// <remarks>
    /// A challenge is exactly the anti-replay, single-ceremony-scoped random value
    /// <see cref="Nonce"/>'s own category already covers, so it carries <see cref="Purpose.Nonce"/>
    /// with <see cref="EntropySource.Csprng"/> — the same shape
    /// <c>Verifiable.OAuth.Pkce.PkceGeneration</c> uses for its own PKCE verifier nonce — rather than
    /// <see cref="Purpose.Data"/>, which <see cref="CredentialId"/> and <see cref="UserHandle"/> use
    /// for opaque, non-random identifiers.
    /// </remarks>
    public static Tag Challenge { get; } = Tag.Create(Purpose.Nonce).With(EntropySource.Csprng);

    /// <summary>
    /// Tag for an <c>authenticatorBioEnrollment</c> fingerprint template identifier
    /// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
    /// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, <c>templateId</c>).
    /// </summary>
    /// <remarks>
    /// A template identifier is an opaque byte string the authenticator mints (CTAP 2.3 §6.7.4, step 8:
    /// "The authenticator generates templateId for new enrollment") with no cryptographic structure of
    /// its own — the platform treats it purely as an identifier, mirroring <see cref="CredentialId"/>'s
    /// own <see cref="Purpose.Data"/>/raw-encoding shape exactly.
    /// </remarks>
    public static Tag BioEnrollmentTemplateId { get; } = Tag.Create(Purpose.Data).With(EncodingScheme.Raw);
}
