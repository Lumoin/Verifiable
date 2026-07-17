using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapClientPinResponseDelegate"/>: encodes an
/// <c>authenticatorClientPIN</c> response model into its CTAP2-canonical CBOR payload bytes — the
/// authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>. The response
/// map's keys (<c>keyAgreement</c>=1 .. <c>uvRetries</c>=5) are already in ascending numeric order,
/// so writing any present Optional member in that fixed order is sufficient — no run-time sort is
/// needed, mirroring <see cref="CtapGetInfoResponseCborWriter"/>'s convention. <c>keyAgreement</c>'s
/// nested COSE_Key reuses <see cref="CredentialPublicKeyCborWriter"/> — CTAP 2.3 §6.5.5's own
/// constraint that this COSE_Key "MUST contain the optional alg parameter and MUST NOT contain any
/// other optional parameters" is enforced by <see cref="Authenticator.Automata.CtapPinUvAuthProtocol.GetPublicKey"/>,
/// which is the only production caller that ever builds the <see cref="CoseKey"/> this writer emits.
/// </remarks>
public static class CtapClientPinResponseCborWriter
{
    /// <summary>
    /// Encodes <paramref name="response"/> into its CTAP2-canonical CBOR payload bytes.
    /// Method-group-compatible with <see cref="EncodeCtapClientPinResponseDelegate"/>.
    /// </summary>
    /// <param name="response">The response model to encode.</param>
    /// <returns>The encoded payload, tagged <see cref="Fido2BufferTags.CtapClientPinResponsePayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="response"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapClientPinResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (response.KeyAgreement is not null ? 1 : 0)
            + (response.PinUvAuthToken is not null ? 1 : 0)
            + (response.PinRetries is not null ? 1 : 0)
            + (response.PowerCycleState is not null ? 1 : 0)
            + (response.UvRetries is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(response.KeyAgreement is CoseKey keyAgreement)
        {
            writer.WriteInt32(WellKnownCtapClientPinResponseKeys.KeyAgreement);
            writer.WriteEncodedValue(CredentialPublicKeyCborWriter.Write(keyAgreement).Span);
        }

        if(response.PinUvAuthToken is ReadOnlyMemory<byte> pinUvAuthToken)
        {
            writer.WriteInt32(WellKnownCtapClientPinResponseKeys.PinUvAuthToken);
            writer.WriteByteString(pinUvAuthToken.Span);
        }

        if(response.PinRetries is int pinRetries)
        {
            writer.WriteInt32(WellKnownCtapClientPinResponseKeys.PinRetries);
            writer.WriteInt32(pinRetries);
        }

        if(response.PowerCycleState is bool powerCycleState)
        {
            writer.WriteInt32(WellKnownCtapClientPinResponseKeys.PowerCycleState);
            writer.WriteBoolean(powerCycleState);
        }

        if(response.UvRetries is int uvRetries)
        {
            writer.WriteInt32(WellKnownCtapClientPinResponseKeys.UvRetries);
            writer.WriteInt32(uvRetries);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapClientPinResponsePayload);
    }
}
