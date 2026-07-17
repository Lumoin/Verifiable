using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapMakeCredentialResponseDelegate"/>: encodes an
/// <c>authenticatorMakeCredential</c> response model into its CTAP2-canonical CBOR payload — the
/// authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>. The response's keys
/// (<c>fmt</c>=1, <c>authData</c>=2, <c>attStmt</c>=3, <c>epAtt</c>=4, <c>largeBlobKey</c>=5) are already
/// in ascending order, so no run-time sort is needed, mirroring <see cref="CtapGetInfoResponseCborWriter"/>'s
/// own convention — <c>epAtt</c> is written BETWEEN the <c>attStmt</c> and <c>largeBlobKey</c> blocks
/// (waveep R9, trap 5/2), never appended after <c>largeBlobKey</c>: an enterprise-attested resident
/// credential with a <c>largeBlobKey</c> also requested is a genuinely reachable combination whose
/// <c>epAtt</c>/<c>largeBlobKey</c> wire order must stay canonical.
/// </remarks>
public static class CtapMakeCredentialResponseCborWriter
{
    /// <summary>
    /// Encodes <paramref name="response"/> into its CTAP2-canonical CBOR payload bytes.
    /// Method-group-compatible with <see cref="EncodeCtapMakeCredentialResponseDelegate"/>.
    /// </summary>
    /// <param name="response">The response model to encode.</param>
    /// <returns>The encoded payload, tagged <see cref="Fido2BufferTags.CtapMakeCredentialResponsePayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="response"/> or its <c>Fmt</c> member is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapMakeCredentialResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(response.Fmt);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 2
            + (response.AttStmt is not null ? 1 : 0)
            + (response.EpAtt.HasValue ? 1 : 0)
            + (response.LargeBlobKey is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.Fmt);
        writer.WriteTextString(response.Fmt);

        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.AuthData);
        writer.WriteByteString(response.AuthData.Span);

        if(response.AttStmt is ReadOnlyMemory<byte> attStmt)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.AttStmt);
            writer.WriteEncodedValue(attStmt.Span);
        }

        //R9: the writer emits whenever EpAtt has a value at all — a codec is faithful, so a foreign
        //present-false round-trips unchanged; only this authenticator's OWN response-build site (never
        //this codec) chooses to omit rather than assert false (trap 18).
        if(response.EpAtt is bool epAtt)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.EpAtt);
            writer.WriteBoolean(epAtt);
        }

        if(response.LargeBlobKey is ReadOnlyMemory<byte> largeBlobKey)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.LargeBlobKey);
            writer.WriteByteString(largeBlobKey.Span);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapMakeCredentialResponsePayload);
    }
}
