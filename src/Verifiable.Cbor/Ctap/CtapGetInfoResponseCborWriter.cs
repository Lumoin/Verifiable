using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapGetInfoResponseDelegate"/>: encodes an
/// <c>authenticatorGetInfo</c> response model into CTAP2-canonical CBOR using
/// <see cref="System.Formats.Cbor"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// CTAP 2.3, section 8: Message Encoding</see> requires the CTAP2 canonical CBOR encoding form:
/// definite-length maps and arrays only, integers and length prefixes encoded as small as possible,
/// and map keys sorted ascending (shorter-key-first, then byte-wise lexical for equal-length keys).
/// This is the FIRST CTAP2-canonical CBOR <em>writer</em> this library ships — every existing
/// <c>Verifiable.Cbor.Fido2</c> reader already decodes with <see cref="CborConformanceMode.Ctap2Canonical"/>,
/// but nothing writes in that mode.
/// </para>
/// <para>
/// The outer response map's keys (<c>versions</c>=1, <c>extensions</c>=2, <c>aaguid</c>=3,
/// <c>options</c>=4, <c>pinUvAuthProtocols</c>=6, <c>maxCredentialCountInList</c>=0x07,
/// <c>algorithms</c>=0x0A, <c>maxSerializedLargeBlobArray</c>=0x0B, <c>forcePINChange</c>=0x0C,
/// <c>minPINLength</c>=0x0D, <c>firmwareVersion</c>=0x0E, <c>maxRPIDsForSetMinPINLength</c>=0x10,
/// <c>preferredPlatformUvAttempts</c>=0x11, <c>uvModality</c>=0x12,
/// <c>remainingDiscoverableCredentials</c>=0x14, <c>authenticatorConfigCommands</c>=0x1F) are already
/// in ascending numeric order, so writing the Required members first, then any present Optional
/// member, in that fixed order, is sufficient — no run-time sort is needed. The <c>algorithms</c>
/// member's own elements (<see cref="Verifiable.Cbor.Ctap.CtapCommandEntityCborCodec.WriteParametersArray"/>)
/// carry no canonical-order rule of their own — a CBOR array's element order is caller-supplied wire
/// order, here the most-to-least-preferred advertisement order; only the element MAPS' own <c>"alg"</c>/
/// <c>"type"</c> keys are text-keyed canonical (length-first: <c>"alg"</c> (3) before <c>"type"</c> (4)).
/// The nested <c>options</c> map uses text-string keys instead, which the
/// canonical sort rule orders by LENGTH first, then byte-wise LEXICALLY for equal-length keys:
/// <c>"ep"</c> (2) precedes <c>"rk"</c> (2) precedes <c>"uv"</c> (2) — a length-2 THREE-WAY tie, broken
/// lexically since <c>'e'</c> (0x65) precedes <c>'r'</c> (0x72) precedes <c>'u'</c> (0x75) — precedes
/// <c>"plat"</c> (4) precedes <c>"alwaysUv"</c> (8) precedes <c>"credMgmt"</c> (8) — a length-8 tie,
/// broken lexically since <c>'a'</c> (0x61) precedes
/// <c>'c'</c> (0x63) — precedes <c>"authnrCfg"</c> (9) precedes <c>"bioEnroll"</c> (9) precedes
/// <c>"clientPin"</c> (9) — a length-9 THREE-WAY tie, broken lexically ('a' &lt; 'b' &lt; 'c') —
/// precedes <c>"largeBlobs"</c> (10, no tie) precedes
/// <c>"uvBioEnroll"</c> (11) precedes <c>"pinUvAuthToken"</c> (14) precedes
/// <c>"setMinPINLength"</c> (15) precedes <c>"makeCredUvNotRqd"</c> (16).
/// </para>
/// </remarks>
public static class CtapGetInfoResponseCborWriter
{
    /// <summary>
    /// Encodes <paramref name="response"/> into its CTAP2-canonical CBOR payload bytes.
    /// Method-group-compatible with <see cref="EncodeCtapGetInfoResponseDelegate"/>.
    /// </summary>
    /// <param name="response">The response model to encode.</param>
    /// <returns>The encoded payload, tagged as <see cref="Fido2BufferTags.CtapGetInfoResponsePayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="response"/> or its <c>Versions</c> member is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapGetInfoResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(response.Versions);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 2
            + (response.Extensions is not null ? 1 : 0)
            + (response.Options is not null ? 1 : 0)
            + (response.PinUvAuthProtocols is not null ? 1 : 0)
            + (response.MaxCredentialCountInList is not null ? 1 : 0)
            + (response.Algorithms is not null ? 1 : 0)
            + (response.MaxSerializedLargeBlobArray is not null ? 1 : 0)
            + (response.ForcePinChange is not null ? 1 : 0)
            + (response.MinPinLength is not null ? 1 : 0)
            + (response.FirmwareVersion is not null ? 1 : 0)
            + (response.MaxRpIdsForSetMinPinLength is not null ? 1 : 0)
            + (response.PreferredPlatformUvAttempts is not null ? 1 : 0)
            + (response.UvModality is not null ? 1 : 0)
            + (response.RemainingDiscoverableCredentials is not null ? 1 : 0)
            + (response.AuthenticatorConfigCommands is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Versions);
        WriteStringArray(writer, response.Versions);

        if(response.Extensions is IReadOnlyList<string> extensions)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Extensions);
            WriteStringArray(writer, extensions);
        }

        writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Aaguid);
        Span<byte> aaguidBytes = stackalloc byte[16];
        _ = response.Aaguid.TryWriteBytes(aaguidBytes, bigEndian: true, out _);
        writer.WriteByteString(aaguidBytes);

        if(response.Options is CtapGetInfoOptions options)
        {
            WriteOptions(writer, options);
        }

        if(response.PinUvAuthProtocols is IReadOnlyList<int> pinUvAuthProtocols)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.PinUvAuthProtocols);
            writer.WriteStartArray(pinUvAuthProtocols.Count);
            foreach(int protocolId in pinUvAuthProtocols)
            {
                writer.WriteInt32(protocolId);
            }

            writer.WriteEndArray();
        }

        if(response.MaxCredentialCountInList is int maxCredentialCountInList)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.MaxCredentialCountInList);
            writer.WriteInt32(maxCredentialCountInList);
        }

        if(response.Algorithms is IReadOnlyList<PublicKeyCredentialParameters> algorithms)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Algorithms);
            CtapCommandEntityCborCodec.WriteParametersArray(writer, algorithms);
        }

        if(response.MaxSerializedLargeBlobArray is int maxSerializedLargeBlobArray)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.MaxSerializedLargeBlobArray);
            writer.WriteInt32(maxSerializedLargeBlobArray);
        }

        if(response.ForcePinChange is bool forcePinChange)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.ForcePinChange);
            writer.WriteBoolean(forcePinChange);
        }

        if(response.MinPinLength is int minPinLength)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.MinPinLength);
            writer.WriteInt32(minPinLength);
        }

        if(response.FirmwareVersion is int firmwareVersion)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.FirmwareVersion);
            writer.WriteInt32(firmwareVersion);
        }

        if(response.MaxRpIdsForSetMinPinLength is int maxRpIdsForSetMinPinLength)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.MaxRpIdsForSetMinPinLength);
            writer.WriteInt32(maxRpIdsForSetMinPinLength);
        }

        if(response.PreferredPlatformUvAttempts is int preferredPlatformUvAttempts)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.PreferredPlatformUvAttempts);
            writer.WriteInt32(preferredPlatformUvAttempts);
        }

        if(response.UvModality is int uvModality)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.UvModality);
            writer.WriteInt32(uvModality);
        }

        if(response.RemainingDiscoverableCredentials is int remainingDiscoverableCredentials)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.RemainingDiscoverableCredentials);
            writer.WriteInt32(remainingDiscoverableCredentials);
        }

        if(response.AuthenticatorConfigCommands is IReadOnlyList<int> authenticatorConfigCommands)
        {
            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.AuthenticatorConfigCommands);
            writer.WriteStartArray(authenticatorConfigCommands.Count);
            foreach(int subCommand in authenticatorConfigCommands)
            {
                writer.WriteInt32(subCommand);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapGetInfoResponsePayload);

        //Writes a definite-length CBOR array of text strings, shared by the versions and
        //extensions members (both "Array of strings" per the response structure table).
        static void WriteStringArray(CborWriter writer, IReadOnlyList<string> values)
        {
            writer.WriteStartArray(values.Count);
            foreach(string value in values)
            {
                writer.WriteTextString(value);
            }

            writer.WriteEndArray();
        }

        //Writes the options member: a map of the option IDs the response carries, in canonical
        //key order — shortest key first, then byte-wise lexical for equal-length keys: "ep" <
        //"rk" < "uv" (the length-2 THREE-WAY tie, 'e' 0x65 < 'r' 0x72 < 'u' 0x75) < "plat" <
        //"alwaysUv" < "credMgmt" (the
        //length-8 tie, "alwaysUv" < "credMgmt" since 'a' 0x61 < 'c' 0x63) < "authnrCfg" <
        //"bioEnroll" < "clientPin" (the length-9 THREE-WAY tie, 'a' < 'b' < 'c') < "largeBlobs"
        //(length 10, no tie) < "uvBioEnroll" < "pinUvAuthToken" < "setMinPINLength" <
        //"makeCredUvNotRqd" — regardless of which subset is actually present.
        static void WriteOptions(CborWriter writer, CtapGetInfoOptions options)
        {
            int optionCount = (options.Ep.HasValue ? 1 : 0)
                + (options.ResidentKey.HasValue ? 1 : 0)
                + (options.Uv.HasValue ? 1 : 0)
                + (options.Platform.HasValue ? 1 : 0)
                + (options.AlwaysUv.HasValue ? 1 : 0)
                + (options.CredMgmt.HasValue ? 1 : 0)
                + (options.AuthnrCfg.HasValue ? 1 : 0)
                + (options.BioEnroll.HasValue ? 1 : 0)
                + (options.ClientPin.HasValue ? 1 : 0)
                + (options.LargeBlobs.HasValue ? 1 : 0)
                + (options.UvBioEnroll.HasValue ? 1 : 0)
                + (options.PinUvAuthToken.HasValue ? 1 : 0)
                + (options.SetMinPinLength.HasValue ? 1 : 0)
                + (options.MakeCredUvNotRqd.HasValue ? 1 : 0);

            writer.WriteInt32(WellKnownCtapGetInfoMemberKeys.Options);
            writer.WriteStartMap(optionCount);

            if(options.Ep is bool ep)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.Ep);
                writer.WriteBoolean(ep);
            }

            if(options.ResidentKey is bool residentKey)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.Rk);
                writer.WriteBoolean(residentKey);
            }

            if(options.Uv is bool uv)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.Uv);
                writer.WriteBoolean(uv);
            }

            if(options.Platform is bool platform)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.Plat);
                writer.WriteBoolean(platform);
            }

            if(options.AlwaysUv is bool alwaysUv)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.AlwaysUv);
                writer.WriteBoolean(alwaysUv);
            }

            if(options.CredMgmt is bool credMgmt)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.CredMgmt);
                writer.WriteBoolean(credMgmt);
            }

            if(options.AuthnrCfg is bool authnrCfg)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.AuthnrCfg);
                writer.WriteBoolean(authnrCfg);
            }

            if(options.BioEnroll is bool bioEnroll)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.BioEnroll);
                writer.WriteBoolean(bioEnroll);
            }

            if(options.ClientPin is bool clientPin)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.ClientPin);
                writer.WriteBoolean(clientPin);
            }

            if(options.LargeBlobs is bool largeBlobs)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.LargeBlobs);
                writer.WriteBoolean(largeBlobs);
            }

            if(options.UvBioEnroll is bool uvBioEnroll)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.UvBioEnroll);
                writer.WriteBoolean(uvBioEnroll);
            }

            if(options.PinUvAuthToken is bool pinUvAuthToken)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.PinUvAuthToken);
                writer.WriteBoolean(pinUvAuthToken);
            }

            if(options.SetMinPinLength is bool setMinPinLength)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.SetMinPinLength);
                writer.WriteBoolean(setMinPinLength);
            }

            if(options.MakeCredUvNotRqd is bool makeCredUvNotRqd)
            {
                writer.WriteTextString(WellKnownCtapGetInfoOptionIds.MakeCredUvNotRqd);
                writer.WriteBoolean(makeCredUvNotRqd);
            }

            writer.WriteEndMap();
        }
    }
}
