using System.Buffers.Binary;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// Writes the binary <c>authData</c> wire format from its constituent fields — the production
/// counterpart to <see cref="AuthenticatorDataReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
/// The wire layout is <c>rpIdHash</c> (32) | <c>flags</c> (1) | <c>signCount</c> (4, big-endian) |
/// [<c>attestedCredentialData</c>] | [<c>extensions</c>].
/// </para>
/// <para>
/// This writer has no CBOR codec dependency: the attested credential data's <c>credentialPublicKey</c>
/// (see <see cref="AttestedCredentialDataToWrite.CredentialPublicKey"/>) and the trailing
/// <c>extensions</c> map both arrive as already-encoded, opaque bytes, so <c>Verifiable.Fido2</c> gains
/// no reference to <c>Verifiable.Cbor</c> — the concrete COSE_Key and extensions codecs are supplied at
/// the composition edge, exactly as <see cref="AuthenticatorDataReader.Read"/>'s
/// <see cref="ReadCredentialPublicKeyDelegate"/> parameter keeps the read side serialization-agnostic.
/// This is one direction of information flow (write only), so unlike the reader, no delegate seam is
/// needed here.
/// </para>
/// <para>
/// Fails closed on caller-supplied inconsistency between the <see cref="AuthenticatorDataFlags"/> bits
/// and the structures actually supplied, rather than silently emitting bytes
/// <see cref="AuthenticatorDataReader.Read"/> could never parse back to the same shape.
/// </para>
/// </remarks>
public static class AuthenticatorDataWriter
{
    /// <summary>The length in bytes of the <c>rpIdHash</c> field.</summary>
    private const int RpIdHashLength = 32;

    /// <summary>The length in bytes of the <c>flags</c> field.</summary>
    private const int FlagsLength = 1;

    /// <summary>The length in bytes of the <c>signCount</c> field.</summary>
    private const int SignCountLength = 4;

    /// <summary>
    /// The combined length of <c>rpIdHash</c>, <c>flags</c>, and <c>signCount</c> — the fixed-size
    /// header preceding the two optional trailing structures.
    /// </summary>
    private const int MinimumLength = RpIdHashLength + FlagsLength + SignCountLength;

    /// <summary>The length in bytes of the <c>aaguid</c> field.</summary>
    private const int AaguidLength = 16;

    /// <summary>The length in bytes of the <c>credentialIdLength</c> field.</summary>
    private const int CredentialIdLengthFieldLength = 2;

    /// <summary>
    /// The combined length of <c>aaguid</c> and <c>credentialIdLength</c>, the fixed-size header
    /// preceding the variable-length <c>credentialId</c>.
    /// </summary>
    private const int AttestedCredentialDataHeaderLength = AaguidLength + CredentialIdLengthFieldLength;

    /// <summary>
    /// The largest permitted <c>credentialId</c> length.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential.</see>
    /// step 25 bounds a returned credential ID to 1023 bytes.
    /// </remarks>
    private const int MaxCredentialIdLength = 1023;


    /// <summary>
    /// Writes <c>authData</c> from its constituent fields.
    /// </summary>
    /// <param name="rpIdHash">
    /// The 32-byte SHA-256 relying party ID hash. Borrowed, not owned — this method reads its bytes and
    /// does not dispose it.
    /// </param>
    /// <param name="flags">
    /// The flags byte. <see cref="AuthenticatorDataFlags.AttestedCredentialDataIncluded"/> MUST agree
    /// with whether <paramref name="attestedCredentialData"/> is supplied, and
    /// <see cref="AuthenticatorDataFlags.ExtensionDataIncluded"/> MUST agree with whether
    /// <paramref name="extensions"/> is non-empty.
    /// </param>
    /// <param name="signCount">The signature counter, written big-endian.</param>
    /// <param name="attestedCredentialData">
    /// The attested credential data to embed, or <see langword="null"/> to omit the structure entirely.
    /// </param>
    /// <param name="extensions">
    /// The already CBOR-encoded extension outputs map to append verbatim, or empty to omit it. Opaque at
    /// this layer — no extension codec dependency exists in this wave.
    /// </param>
    /// <returns>The assembled <c>authData</c> wire bytes, tagged <see cref="Fido2BufferTags.AuthenticatorDataPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rpIdHash"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="rpIdHash"/> is not exactly 32 bytes; <paramref name="flags"/>'s
    /// <see cref="AuthenticatorDataFlags.AttestedCredentialDataIncluded"/> bit disagrees with whether
    /// <paramref name="attestedCredentialData"/> is supplied; <paramref name="flags"/>'s
    /// <see cref="AuthenticatorDataFlags.ExtensionDataIncluded"/> bit disagrees with whether
    /// <paramref name="extensions"/> is non-empty; or <paramref name="attestedCredentialData"/>'s
    /// credential ID exceeds <see cref="MaxCredentialIdLength"/> bytes.
    /// </exception>
    public static TaggedMemory<byte> Write(
        DigestValue rpIdHash,
        AuthenticatorDataFlags flags,
        uint signCount,
        AttestedCredentialDataToWrite? attestedCredentialData = null,
        ReadOnlyMemory<byte> extensions = default)
    {
        ArgumentNullException.ThrowIfNull(rpIdHash);

        if(rpIdHash.Length != RpIdHashLength)
        {
            throw new ArgumentException($"The rpIdHash must be exactly {RpIdHashLength} bytes; was {rpIdHash.Length}.", nameof(rpIdHash));
        }

        if(flags.AttestedCredentialDataIncluded != (attestedCredentialData is not null))
        {
            throw new ArgumentException("The AT flag must be set if and only if attestedCredentialData is supplied.", nameof(flags));
        }

        if(flags.ExtensionDataIncluded != !extensions.IsEmpty)
        {
            throw new ArgumentException("The ED flag must be set if and only if extensions is non-empty.", nameof(flags));
        }

        int attestedLength = 0;
        if(attestedCredentialData is not null)
        {
            ArgumentNullException.ThrowIfNull(attestedCredentialData.CredentialId, nameof(attestedCredentialData));

            if(attestedCredentialData.CredentialId.Length > MaxCredentialIdLength)
            {
                throw new ArgumentException(
                    $"The credential ID length {attestedCredentialData.CredentialId.Length} exceeds the maximum of {MaxCredentialIdLength} bytes.",
                    nameof(attestedCredentialData));
            }

            attestedLength = AttestedCredentialDataHeaderLength + attestedCredentialData.CredentialId.Length + attestedCredentialData.CredentialPublicKey.Length;
        }

        byte[] buffer = new byte[MinimumLength + attestedLength + extensions.Length];

        rpIdHash.AsReadOnlySpan().CopyTo(buffer.AsSpan(0, RpIdHashLength));
        buffer[RpIdHashLength] = flags.Value;
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(RpIdHashLength + FlagsLength, SignCountLength), signCount);

        int offset = MinimumLength;
        if(attestedCredentialData is not null)
        {
            offset += WriteAttestedCredentialData(buffer.AsSpan(offset), attestedCredentialData);
        }

        extensions.Span.CopyTo(buffer.AsSpan(offset));

        return new TaggedMemory<byte>(buffer, Fido2BufferTags.AuthenticatorDataPayload);

        //Writes the attested credential data block (aaguid | credentialIdLength | credentialId |
        //credentialPublicKey) into `destination` and returns the number of bytes written.
        static int WriteAttestedCredentialData(Span<byte> destination, AttestedCredentialDataToWrite attestedCredentialData)
        {
            _ = attestedCredentialData.Aaguid.TryWriteBytes(destination[..AaguidLength], bigEndian: true, out _);
            BinaryPrimitives.WriteUInt16BigEndian(
                destination.Slice(AaguidLength, CredentialIdLengthFieldLength),
                checked((ushort)attestedCredentialData.CredentialId.Length));

            int written = AttestedCredentialDataHeaderLength;
            attestedCredentialData.CredentialId.AsReadOnlySpan().CopyTo(destination[written..]);
            written += attestedCredentialData.CredentialId.Length;

            attestedCredentialData.CredentialPublicKey.Span.CopyTo(destination[written..]);
            written += attestedCredentialData.CredentialPublicKey.Length;

            return written;
        }
    }
}
