using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapGetInfoResponseDelegate"/>: decodes an
/// <c>authenticatorGetInfo</c> response's CTAP2-canonical CBOR payload into its typed model.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>. Read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, mirroring every existing
/// <c>Verifiable.Cbor.Fido2</c> reader. Per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// section 8: Message Encoding</see>'s forward-compatibility rule ("If map keys are present that an
/// implementation does not understand, they MUST be ignored"), any member key or option ID this
/// reader does not model is skipped rather than rejected.
/// </remarks>
public static class CtapGetInfoResponseCborReader
{
    /// <summary>
    /// Decodes <paramref name="payload"/> into a <see cref="CtapGetInfoResponse"/>.
    /// Method-group-compatible with <see cref="DecodeCtapGetInfoResponseDelegate"/>.
    /// </summary>
    /// <param name="payload">The CBOR-encoded response payload.</param>
    /// <returns>The decoded response model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="payload"/> is not valid CTAP2 canonical CBOR, or omits the Required
    /// <c>versions</c> or <c>aaguid</c> member.
    /// </exception>
    public static CtapGetInfoResponse Read(ReadOnlyMemory<byte> payload)
    {
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            List<string>? versions = null;
            List<string>? extensions = null;
            Guid? aaguid = null;
            CtapGetInfoOptions? options = null;
            List<int>? pinUvAuthProtocols = null;
            int? maxCredentialCountInList = null;
            List<PublicKeyCredentialParameters>? algorithms = null;
            int? maxSerializedLargeBlobArray = null;
            bool? forcePinChange = null;
            int? minPinLength = null;
            int? firmwareVersion = null;
            int? maxRpIdsForSetMinPinLength = null;
            int? preferredPlatformUvAttempts = null;
            int? uvModality = null;
            int? remainingDiscoverableCredentials = null;
            List<int>? authenticatorConfigCommands = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                _ = key switch
                {
                    WellKnownCtapGetInfoMemberKeys.Versions => AssignVersions(reader, ref versions),
                    WellKnownCtapGetInfoMemberKeys.Extensions => AssignExtensions(reader, ref extensions),
                    WellKnownCtapGetInfoMemberKeys.Aaguid => AssignAaguid(reader, ref aaguid),
                    WellKnownCtapGetInfoMemberKeys.Options => AssignOptions(reader, ref options),
                    WellKnownCtapGetInfoMemberKeys.PinUvAuthProtocols => AssignPinUvAuthProtocols(reader, ref pinUvAuthProtocols),
                    WellKnownCtapGetInfoMemberKeys.MaxCredentialCountInList => AssignMaxCredentialCountInList(reader, ref maxCredentialCountInList),
                    WellKnownCtapGetInfoMemberKeys.Algorithms => AssignAlgorithms(reader, ref algorithms),
                    WellKnownCtapGetInfoMemberKeys.MaxSerializedLargeBlobArray => AssignMaxSerializedLargeBlobArray(reader, ref maxSerializedLargeBlobArray),
                    WellKnownCtapGetInfoMemberKeys.ForcePinChange => AssignForcePinChange(reader, ref forcePinChange),
                    WellKnownCtapGetInfoMemberKeys.MinPinLength => AssignMinPinLength(reader, ref minPinLength),
                    WellKnownCtapGetInfoMemberKeys.FirmwareVersion => AssignFirmwareVersion(reader, ref firmwareVersion),
                    WellKnownCtapGetInfoMemberKeys.MaxRpIdsForSetMinPinLength => AssignMaxRpIdsForSetMinPinLength(reader, ref maxRpIdsForSetMinPinLength),
                    WellKnownCtapGetInfoMemberKeys.PreferredPlatformUvAttempts => AssignPreferredPlatformUvAttempts(reader, ref preferredPlatformUvAttempts),
                    WellKnownCtapGetInfoMemberKeys.UvModality => AssignUvModality(reader, ref uvModality),
                    WellKnownCtapGetInfoMemberKeys.RemainingDiscoverableCredentials => AssignRemainingDiscoverableCredentials(reader, ref remainingDiscoverableCredentials),
                    WellKnownCtapGetInfoMemberKeys.AuthenticatorConfigCommands => AssignAuthenticatorConfigCommands(reader, ref authenticatorConfigCommands),
                    _ => SkipValue(reader)
                };
            }

            reader.ReadEndMap();

            if(versions is null)
            {
                throw new Fido2FormatException("The authenticatorGetInfo response is missing the required 'versions' (0x01) member.");
            }

            if(aaguid is not Guid resolvedAaguid)
            {
                throw new Fido2FormatException("The authenticatorGetInfo response is missing the required 'aaguid' (0x03) member.");
            }

            return new CtapGetInfoResponse(
                versions, resolvedAaguid, extensions, options, pinUvAuthProtocols, maxSerializedLargeBlobArray,
                forcePinChange, minPinLength, maxRpIdsForSetMinPinLength, preferredPlatformUvAttempts, uvModality,
                remainingDiscoverableCredentials, authenticatorConfigCommands, maxCredentialCountInList, algorithms,
                firmwareVersion);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The authenticatorGetInfo response bytes are not valid CTAP2 canonical CBOR.", exception);
        }

        //Reads a definite-length CBOR array of text strings, shared by the versions and
        //extensions members.
        static List<string> ReadStringArray(CborReader reader)
        {
            int? count = reader.ReadStartArray();
            var values = new List<string>();

            int read = 0;
            while(count is null ? reader.PeekState() != CborReaderState.EndArray : read < count.Value)
            {
                values.Add(reader.ReadTextString());
                read++;
            }

            reader.ReadEndArray();

            return values;
        }

        //Reads a definite-length CBOR array of unsigned integers, used by the pinUvAuthProtocols member.
        static List<int> ReadIntArray(CborReader reader)
        {
            int? count = reader.ReadStartArray();
            var values = new List<int>();

            int read = 0;
            while(count is null ? reader.PeekState() != CborReaderState.EndArray : read < count.Value)
            {
                values.Add(checked((int)reader.ReadInt64()));
                read++;
            }

            reader.ReadEndArray();

            return values;
        }

        //Reads the options member: a map of string option IDs to booleans, tolerating any option
        //ID this reader does not model. Reading is order-independent — the writer's canonical
        //ordering is a write-side-only constraint.
        static CtapGetInfoOptions ReadOptions(CborReader reader)
        {
            int? count = reader.ReadStartMap();
            bool? ep = null;
            bool? residentKey = null;
            bool? uv = null;
            bool? platform = null;
            bool? alwaysUv = null;
            bool? credMgmt = null;
            bool? authnrCfg = null;
            bool? bioEnroll = null;
            bool? clientPin = null;
            bool? largeBlobs = null;
            bool? uvBioEnroll = null;
            bool? pinUvAuthToken = null;
            bool? setMinPinLength = null;
            bool? makeCredUvNotRqd = null;

            int read = 0;
            while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
            {
                string optionId = reader.ReadTextString();
                bool value = reader.ReadBoolean();
                read++;

                _ = optionId switch
                {
                    _ when WellKnownCtapGetInfoOptionIds.IsEp(optionId) => ep = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsRk(optionId) => residentKey = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsUv(optionId) => uv = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsPlat(optionId) => platform = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsAlwaysUv(optionId) => alwaysUv = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsCredMgmt(optionId) => credMgmt = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsAuthnrCfg(optionId) => authnrCfg = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsBioEnroll(optionId) => bioEnroll = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsClientPin(optionId) => clientPin = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsLargeBlobs(optionId) => largeBlobs = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsUvBioEnroll(optionId) => uvBioEnroll = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsPinUvAuthToken(optionId) => pinUvAuthToken = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsSetMinPinLength(optionId) => setMinPinLength = value,
                    _ when WellKnownCtapGetInfoOptionIds.IsMakeCredUvNotRqd(optionId) => makeCredUvNotRqd = value,
                    _ => null
                };
            }

            reader.ReadEndMap();

            return new CtapGetInfoOptions(ep, residentKey, uv, platform, alwaysUv, credMgmt, authnrCfg, bioEnroll, clientPin, largeBlobs, uvBioEnroll, pinUvAuthToken, setMinPinLength, makeCredUvNotRqd);
        }

        //Assigns the decoded versions array to versions.
        static bool AssignVersions(CborReader reader, ref List<string>? versions)
        {
            versions = ReadStringArray(reader);

            return true;
        }

        //Assigns the decoded extensions array to extensions.
        static bool AssignExtensions(CborReader reader, ref List<string>? extensions)
        {
            extensions = ReadStringArray(reader);

            return true;
        }

        //Assigns the decoded AAGUID to aaguid.
        static bool AssignAaguid(CborReader reader, ref Guid? aaguid)
        {
            aaguid = new Guid(reader.ReadByteString(), bigEndian: true);

            return true;
        }

        //Assigns the decoded options map to options.
        static bool AssignOptions(CborReader reader, ref CtapGetInfoOptions? options)
        {
            options = ReadOptions(reader);

            return true;
        }

        //Assigns the decoded PIN/UV auth protocol list to pinUvAuthProtocols.
        static bool AssignPinUvAuthProtocols(CborReader reader, ref List<int>? pinUvAuthProtocols)
        {
            pinUvAuthProtocols = ReadIntArray(reader);

            return true;
        }

        //Assigns the decoded maximum credential-list count to maxCredentialCountInList.
        static bool AssignMaxCredentialCountInList(CborReader reader, ref int? maxCredentialCountInList)
        {
            maxCredentialCountInList = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded PublicKeyCredentialParameters array to algorithms, reusing
        //CtapCommandEntityCborCodec's own PublicKeyCredentialParameters array reader (the same one
        //authenticatorMakeCredential's pubKeyCredParams member uses).
        static bool AssignAlgorithms(CborReader reader, ref List<PublicKeyCredentialParameters>? algorithms)
        {
            algorithms = CtapCommandEntityCborCodec.ReadParametersArray(reader);

            return true;
        }

        //Assigns the decoded maximum serialized large-blob array size to maxSerializedLargeBlobArray.
        static bool AssignMaxSerializedLargeBlobArray(CborReader reader, ref int? maxSerializedLargeBlobArray)
        {
            maxSerializedLargeBlobArray = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded force-PIN-change flag to forcePinChange.
        static bool AssignForcePinChange(CborReader reader, ref bool? forcePinChange)
        {
            forcePinChange = reader.ReadBoolean();

            return true;
        }

        //Assigns the decoded minimum PIN length to minPinLength.
        static bool AssignMinPinLength(CborReader reader, ref int? minPinLength)
        {
            minPinLength = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded firmware version to firmwareVersion.
        static bool AssignFirmwareVersion(CborReader reader, ref int? firmwareVersion)
        {
            firmwareVersion = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded maximum RP-ID count to maxRpIdsForSetMinPinLength.
        static bool AssignMaxRpIdsForSetMinPinLength(CborReader reader, ref int? maxRpIdsForSetMinPinLength)
        {
            maxRpIdsForSetMinPinLength = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded preferred platform UV attempt count to preferredPlatformUvAttempts.
        static bool AssignPreferredPlatformUvAttempts(CborReader reader, ref int? preferredPlatformUvAttempts)
        {
            preferredPlatformUvAttempts = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded UV modality bit-flags to uvModality.
        static bool AssignUvModality(CborReader reader, ref int? uvModality)
        {
            uvModality = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded remaining discoverable credential count to
        //remainingDiscoverableCredentials.
        static bool AssignRemainingDiscoverableCredentials(CborReader reader, ref int? remainingDiscoverableCredentials)
        {
            remainingDiscoverableCredentials = checked((int)reader.ReadInt64());

            return true;
        }

        //Assigns the decoded authenticatorConfig subcommand list to authenticatorConfigCommands.
        static bool AssignAuthenticatorConfigCommands(CborReader reader, ref List<int>? authenticatorConfigCommands)
        {
            authenticatorConfigCommands = ReadIntArray(reader);

            return true;
        }

        //Skips an unmodeled member's value, per section 8's forward-compatibility rule.
        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return false;
        }
    }
}
