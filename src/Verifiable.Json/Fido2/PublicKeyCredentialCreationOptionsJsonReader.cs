using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> reader for the <see cref="PublicKeyCredentialCreationOptionsJsonWriter"/>
/// document shape, reconstructing a <see cref="PublicKeyCredentialCreationOptions"/> — for CLI/test
/// round-trip, since the CR's own <c>parseCreationOptionsFromJSON()</c> is a client (browser)
/// operation this library does not itself perform.
/// </summary>
/// <remarks>
/// Strict, mirroring <see cref="Fido2CredentialRecordJsonReader"/>'s posture: an unrecognised or
/// repeated member is rejected rather than silently skipped, including under <c>extensions</c> (this
/// writer emits only the <c>appidExclude</c>/<c>largeBlob</c>/<c>minPinLength</c>/
/// <c>credentialProtectionPolicy</c>/<c>enforceCredentialProtectionPolicy</c> carve-outs, so a
/// document carrying any other extension identifier did not come from this writer). Unlike
/// <see cref="Fido2CredentialRecordJsonReader"/>, there is no <c>version</c> member to check, since
/// this is the CR's own named wire shape, not a private persistence format.
/// </remarks>
public static class PublicKeyCredentialCreationOptionsJsonReader
{
    private const string RpMember = "rp";
    private const string RpIdMember = "id";
    private const string NameMember = "name";
    private const string UserMember = "user";
    private const string IdMember = "id";
    private const string DisplayNameMember = "displayName";
    private const string ChallengeMember = "challenge";
    private const string PubKeyCredParamsMember = "pubKeyCredParams";
    private const string TypeMember = "type";
    private const string AlgMember = "alg";
    private const string TimeoutMember = "timeout";
    private const string ExcludeCredentialsMember = "excludeCredentials";
    private const string TransportsMember = "transports";
    private const string AuthenticatorSelectionMember = "authenticatorSelection";
    private const string AuthenticatorAttachmentMember = "authenticatorAttachment";
    private const string ResidentKeyMember = "residentKey";
    private const string RequireResidentKeyMember = "requireResidentKey";
    private const string UserVerificationMember = "userVerification";
    private const string HintsMember = "hints";
    private const string AttestationMember = "attestation";
    private const string AttestationFormatsMember = "attestationFormats";
    private const string ExtensionsMember = "extensions";
    private const string SupportMember = "support";
    private const string CredentialProtectionPolicyMember = "credentialProtectionPolicy";
    private const string EnforceCredentialProtectionPolicyMember = "enforceCredentialProtectionPolicy";


    /// <summary>
    /// Bounds JSON nesting depth. The deepest legal path is
    /// <c>excludeCredentials[].transports[]</c> or <c>extensions.largeBlob.support</c> (three levels
    /// below the top object), so 6 is generous while still capping recursion depth at parse time.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 6 };


    /// <summary>
    /// Parses a <see cref="PublicKeyCredentialCreationOptionsJsonWriter"/> document into a
    /// <see cref="PublicKeyCredentialCreationOptions"/>.
    /// </summary>
    /// <param name="document">The raw document bytes.</param>
    /// <param name="pool">The memory pool <c>user.id</c>/descriptor <c>id</c> carriers rent from.</param>
    /// <returns>The parsed <see cref="PublicKeyCredentialCreationOptions"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="document"/> is not valid JSON, its top level is not an object, a required
    /// member is missing or has the wrong JSON type, an unrecognised member is present, a member name
    /// repeats, a binary member is not valid base64url, an enum-backed member's wire value is not
    /// registered, or nesting exceeds the depth bound.
    /// </exception>
    public static PublicKeyCredentialCreationOptions Read(ReadOnlyMemory<byte> document, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            return ReadObject(document.Span, pool);
        }
        catch(Exception exception) when(exception is JsonException or FormatException or OverflowException or ArgumentOutOfRangeException)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions document is not well-formed.", exception);
        }
    }


    private static PublicKeyCredentialCreationOptions ReadObject(ReadOnlySpan<byte> document, MemoryPool<byte> pool)
    {
        Utf8JsonReader reader = new(document, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        PublicKeyCredentialRpEntity? rp = null;
        PublicKeyCredentialUserEntity? user = null;
        string? challenge = null;
        List<PublicKeyCredentialParameters>? pubKeyCredParams = null;
        uint? timeout = null;
        List<PublicKeyCredentialDescriptor>? excludeCredentials = null;
        AuthenticatorSelectionCriteria? authenticatorSelection = null;
        List<PublicKeyCredentialHint>? hints = null;
        AttestationConveyancePreference? attestation = null;
        List<string>? attestationFormats = null;
        string? appIdExclude = null;
        Fido2LargeBlobRegistrationExtensionInput? largeBlob = null;
        bool? minPinLength = null;
        Fido2CredProtectRegistrationExtensionInput? credProtect = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The PublicKeyCredentialCreationOptions member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The PublicKeyCredentialCreationOptions member '{memberName}' is truncated.");
            }

            _ = memberName switch
            {
                RpMember => AssignRp(ref reader, out rp),
                UserMember => AssignUser(ref reader, pool, out user),
                ChallengeMember => AssignChallenge(ref reader, memberName, out challenge),
                PubKeyCredParamsMember => AssignPubKeyCredParams(ref reader, out pubKeyCredParams),
                TimeoutMember => AssignTimeout(ref reader, memberName, out timeout),
                ExcludeCredentialsMember => AssignExcludeCredentials(ref reader, memberName, pool, out excludeCredentials),
                AuthenticatorSelectionMember => AssignAuthenticatorSelection(ref reader, out authenticatorSelection),
                HintsMember => AssignHints(ref reader, memberName, out hints),
                AttestationMember => AssignAttestation(ref reader, memberName, out attestation),
                AttestationFormatsMember => AssignAttestationFormats(ref reader, memberName, out attestationFormats),
                ExtensionsMember => AssignExtensions(ref reader, out appIdExclude, out largeBlob, out minPinLength, out credProtect),
                _ => throw new Fido2FormatException($"The PublicKeyCredentialCreationOptions member '{memberName}' is not recognised.")
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions object is not terminated.");
        }

        if(reader.Read())
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions document carries content trailing its closing brace.");
        }

        if(rp is null)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'rp' is required.");
        }

        if(user is null)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'user' is required.");
        }

        if(challenge is null)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'challenge' is required.");
        }

        if(pubKeyCredParams is null)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'pubKeyCredParams' is required.");
        }

        return new PublicKeyCredentialCreationOptions
        {
            Rp = rp,
            User = user,
            Challenge = challenge,
            PubKeyCredParams = pubKeyCredParams,
            Timeout = timeout,
            ExcludeCredentials = excludeCredentials,
            AuthenticatorSelection = authenticatorSelection,
            Hints = hints,
            Attestation = attestation,
            AttestationFormats = attestationFormats,
            AppIdExclude = appIdExclude,
            LargeBlob = largeBlob,
            MinPinLength = minPinLength,
            CredProtect = credProtect
        };

        static bool AssignRp(ref Utf8JsonReader reader, out PublicKeyCredentialRpEntity? rp)
        {
            rp = ReadRpEntity(ref reader);

            return true;
        }

        static bool AssignUser(ref Utf8JsonReader reader, MemoryPool<byte> pool, out PublicKeyCredentialUserEntity? user)
        {
            user = ReadUserEntity(ref reader, pool);

            return true;
        }

        static bool AssignChallenge(ref Utf8JsonReader reader, string memberName, out string? challenge)
        {
            challenge = ReadRequiredString(ref reader, memberName);

            return true;
        }

        static bool AssignPubKeyCredParams(ref Utf8JsonReader reader, out List<PublicKeyCredentialParameters>? pubKeyCredParams)
        {
            pubKeyCredParams = ReadPubKeyCredParams(ref reader);

            return true;
        }

        static bool AssignTimeout(ref Utf8JsonReader reader, string memberName, out uint? timeout)
        {
            timeout = ReadRequiredUInt32(ref reader, memberName);

            return true;
        }

        static bool AssignExcludeCredentials(ref Utf8JsonReader reader, string memberName, MemoryPool<byte> pool, out List<PublicKeyCredentialDescriptor>? excludeCredentials)
        {
            excludeCredentials = ReadDescriptors(ref reader, memberName, pool);

            return true;
        }

        static bool AssignAuthenticatorSelection(ref Utf8JsonReader reader, out AuthenticatorSelectionCriteria? authenticatorSelection)
        {
            authenticatorSelection = ReadAuthenticatorSelection(ref reader);

            return true;
        }

        static bool AssignHints(ref Utf8JsonReader reader, string memberName, out List<PublicKeyCredentialHint>? hints)
        {
            hints = ReadHints(ref reader, memberName);

            return true;
        }

        static bool AssignAttestation(ref Utf8JsonReader reader, string memberName, out AttestationConveyancePreference? attestation)
        {
            attestation = WellKnownAttestationConveyancePreferences.FromWireValue(ReadRequiredString(ref reader, memberName));

            return true;
        }

        static bool AssignAttestationFormats(ref Utf8JsonReader reader, string memberName, out List<string>? attestationFormats)
        {
            attestationFormats = ReadStringArray(ref reader, memberName);

            return true;
        }

        //Assigns all four extension-derived outputs together, since 'extensions' decodes as one nested
        //object producing appIdExclude/largeBlob/minPinLength/credProtect in a single pass.
        static bool AssignExtensions(
            ref Utf8JsonReader reader,
            out string? appIdExclude,
            out Fido2LargeBlobRegistrationExtensionInput? largeBlob,
            out bool? minPinLength,
            out Fido2CredProtectRegistrationExtensionInput? credProtect)
        {
            (appIdExclude, largeBlob, minPinLength, credProtect) = ReadExtensions(ref reader);

            return true;
        }
    }


    private static PublicKeyCredentialRpEntity ReadRpEntity(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'rp' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? id = null;
        string? name = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The 'rp' member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The 'rp' member '{memberName}' is truncated.");
            }

            _ = memberName switch
            {
                RpIdMember => AssignId(ref reader, memberName, out id),
                NameMember => AssignName(ref reader, memberName, out name),
                _ => throw new Fido2FormatException($"The 'rp' member '{memberName}' is not recognised.")
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The 'rp' object is not terminated.");
        }

        if(name is null)
        {
            throw new Fido2FormatException("The 'rp' member 'name' is required.");
        }

        return new PublicKeyCredentialRpEntity { Id = id, Name = name };

        static bool AssignId(ref Utf8JsonReader reader, string memberName, out string? id)
        {
            id = ReadRequiredString(ref reader, memberName);

            return true;
        }

        static bool AssignName(ref Utf8JsonReader reader, string memberName, out string? name)
        {
            name = ReadRequiredString(ref reader, memberName);

            return true;
        }
    }


    private static PublicKeyCredentialUserEntity ReadUserEntity(ref Utf8JsonReader reader, MemoryPool<byte> pool)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'user' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        ReadOnlyMemory<byte>? idBytes = null;
        string? name = null;
        string? displayName = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The 'user' member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The 'user' member '{memberName}' is truncated.");
            }

            _ = memberName switch
            {
                IdMember => AssignIdBytes(ref reader, memberName, out idBytes),
                NameMember => AssignName(ref reader, memberName, out name),
                DisplayNameMember => AssignDisplayName(ref reader, memberName, out displayName),
                _ => throw new Fido2FormatException($"The 'user' member '{memberName}' is not recognised.")
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The 'user' object is not terminated.");
        }

        if(idBytes is null)
        {
            throw new Fido2FormatException("The 'user' member 'id' is required.");
        }

        if(name is null)
        {
            throw new Fido2FormatException("The 'user' member 'name' is required.");
        }

        if(displayName is null)
        {
            throw new Fido2FormatException("The 'user' member 'displayName' is required.");
        }

        return new PublicKeyCredentialUserEntity
        {
            Id = UserHandle.Create(idBytes.Value.Span, pool),
            Name = name,
            DisplayName = displayName
        };

        static bool AssignIdBytes(ref Utf8JsonReader reader, string memberName, out ReadOnlyMemory<byte>? idBytes)
        {
            idBytes = ReadRequiredBinary(ref reader, memberName);

            return true;
        }

        static bool AssignName(ref Utf8JsonReader reader, string memberName, out string? name)
        {
            name = ReadRequiredString(ref reader, memberName);

            return true;
        }

        static bool AssignDisplayName(ref Utf8JsonReader reader, string memberName, out string? displayName)
        {
            displayName = ReadRequiredString(ref reader, memberName);

            return true;
        }
    }


    private static List<PublicKeyCredentialParameters> ReadPubKeyCredParams(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'pubKeyCredParams' MUST be a JSON array.");
        }

        List<PublicKeyCredentialParameters> parameters = [];
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                throw new Fido2FormatException("An element of 'pubKeyCredParams' MUST be a JSON object.");
            }

            HashSet<string> seenMembers = new(StringComparer.Ordinal);
            string? type = null;
            int? alg = null;

            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"A 'pubKeyCredParams' element member '{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"A 'pubKeyCredParams' element member '{memberName}' is truncated.");
                }

                _ = memberName switch
                {
                    TypeMember => AssignType(ref reader, memberName, out type),
                    AlgMember => AssignAlg(ref reader, memberName, out alg),
                    _ => throw new Fido2FormatException($"A 'pubKeyCredParams' element member '{memberName}' is not recognised.")
                };
            }

            if(type is null)
            {
                throw new Fido2FormatException("A 'pubKeyCredParams' element member 'type' is required.");
            }

            if(alg is null)
            {
                throw new Fido2FormatException("A 'pubKeyCredParams' element member 'alg' is required.");
            }

            parameters.Add(new PublicKeyCredentialParameters { Type = type, Alg = alg.Value });
        }

        return parameters;

        static bool AssignType(ref Utf8JsonReader reader, string memberName, out string? type)
        {
            type = ReadRequiredString(ref reader, memberName);

            return true;
        }

        static bool AssignAlg(ref Utf8JsonReader reader, string memberName, out int? alg)
        {
            alg = ReadRequiredInt32(ref reader, memberName);

            return true;
        }
    }


    private static List<PublicKeyCredentialDescriptor> ReadDescriptors(ref Utf8JsonReader reader, string memberName, MemoryPool<byte> pool)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException($"The PublicKeyCredentialCreationOptions member '{memberName}' MUST be a JSON array.");
        }

        List<PublicKeyCredentialDescriptor> descriptors = [];
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                throw new Fido2FormatException($"An element of '{memberName}' MUST be a JSON object.");
            }

            HashSet<string> seenMembers = new(StringComparer.Ordinal);
            string? type = null;
            ReadOnlyMemory<byte>? idBytes = null;
            List<string>? transports = null;

            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string elementMemberName = reader.GetString()!;
                if(!seenMembers.Add(elementMemberName))
                {
                    throw new Fido2FormatException($"A '{memberName}' element member '{elementMemberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"A '{memberName}' element member '{elementMemberName}' is truncated.");
                }

                _ = elementMemberName switch
                {
                    TypeMember => AssignType(ref reader, elementMemberName, out type),
                    IdMember => AssignIdBytes(ref reader, elementMemberName, out idBytes),
                    TransportsMember => AssignTransports(ref reader, elementMemberName, out transports),
                    _ => throw new Fido2FormatException($"A '{memberName}' element member '{elementMemberName}' is not recognised.")
                };
            }

            if(type is null)
            {
                throw new Fido2FormatException($"A '{memberName}' element member 'type' is required.");
            }

            if(idBytes is null)
            {
                throw new Fido2FormatException($"A '{memberName}' element member 'id' is required.");
            }

            descriptors.Add(new PublicKeyCredentialDescriptor
            {
                Type = type,
                Id = CredentialId.Create(idBytes.Value.Span, pool),
                Transports = transports
            });
        }

        return descriptors;

        static bool AssignType(ref Utf8JsonReader reader, string elementMemberName, out string? type)
        {
            type = ReadRequiredString(ref reader, elementMemberName);

            return true;
        }

        static bool AssignIdBytes(ref Utf8JsonReader reader, string elementMemberName, out ReadOnlyMemory<byte>? idBytes)
        {
            idBytes = ReadRequiredBinary(ref reader, elementMemberName);

            return true;
        }

        static bool AssignTransports(ref Utf8JsonReader reader, string elementMemberName, out List<string>? transports)
        {
            transports = ReadStringArray(ref reader, elementMemberName);

            return true;
        }
    }


    private static AuthenticatorSelectionCriteria ReadAuthenticatorSelection(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'authenticatorSelection' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? authenticatorAttachment = null;
        ResidentKeyRequirement? residentKey = null;
        bool? requireResidentKey = null;
        UserVerificationRequirement? userVerification = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The 'authenticatorSelection' member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The 'authenticatorSelection' member '{memberName}' is truncated.");
            }

            _ = memberName switch
            {
                AuthenticatorAttachmentMember => AssignAuthenticatorAttachment(ref reader, memberName, out authenticatorAttachment),
                ResidentKeyMember => AssignResidentKey(ref reader, memberName, out residentKey),
                RequireResidentKeyMember => AssignRequireResidentKey(ref reader, memberName, out requireResidentKey),
                UserVerificationMember => AssignUserVerification(ref reader, memberName, out userVerification),
                _ => throw new Fido2FormatException($"The 'authenticatorSelection' member '{memberName}' is not recognised.")
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The 'authenticatorSelection' object is not terminated.");
        }

        return new AuthenticatorSelectionCriteria
        {
            AuthenticatorAttachment = authenticatorAttachment,
            ResidentKey = residentKey,
            RequireResidentKey = requireResidentKey ?? false,
            UserVerification = userVerification ?? UserVerificationRequirement.Preferred
        };

        static bool AssignAuthenticatorAttachment(ref Utf8JsonReader reader, string memberName, out string? authenticatorAttachment)
        {
            authenticatorAttachment = ReadRequiredString(ref reader, memberName);

            return true;
        }

        static bool AssignResidentKey(ref Utf8JsonReader reader, string memberName, out ResidentKeyRequirement? residentKey)
        {
            residentKey = WellKnownResidentKeyRequirements.FromWireValue(ReadRequiredString(ref reader, memberName));

            return true;
        }

        static bool AssignRequireResidentKey(ref Utf8JsonReader reader, string memberName, out bool? requireResidentKey)
        {
            requireResidentKey = ReadRequiredBoolean(ref reader, memberName);

            return true;
        }

        static bool AssignUserVerification(ref Utf8JsonReader reader, string memberName, out UserVerificationRequirement? userVerification)
        {
            userVerification = WellKnownUserVerificationRequirements.FromWireValue(ReadRequiredString(ref reader, memberName));

            return true;
        }
    }


    private static List<PublicKeyCredentialHint> ReadHints(ref Utf8JsonReader reader, string memberName)
    {
        List<string> values = ReadStringArray(ref reader, memberName);
        List<PublicKeyCredentialHint> hints = new(values.Count);
        foreach(string value in values)
        {
            hints.Add(WellKnownPublicKeyCredentialHints.FromWireValue(value));
        }

        return hints;
    }


    private static (string? AppIdExclude, Fido2LargeBlobRegistrationExtensionInput? LargeBlob, bool? MinPinLength, Fido2CredProtectRegistrationExtensionInput? CredProtect) ReadExtensions(
        ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialCreationOptions member 'extensions' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? appIdExclude = null;
        Fido2LargeBlobRegistrationExtensionInput? largeBlob = null;
        bool? minPinLength = null;
        string? credentialProtectionPolicy = null;
        bool? enforceCredentialProtectionPolicy = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string identifier = reader.GetString()!;
            if(!seenMembers.Add(identifier))
            {
                throw new Fido2FormatException($"The 'extensions' member '{identifier}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The 'extensions' member '{identifier}' is truncated.");
            }

            _ = identifier switch
            {
                var id when WellKnownWebAuthnExtensionIdentifiers.IsAppIdExclude(id) => AssignAppIdExclude(ref reader, id, out appIdExclude),
                var id when WellKnownWebAuthnExtensionIdentifiers.IsLargeBlob(id) => AssignLargeBlob(ref reader, out largeBlob),
                var id when WellKnownWebAuthnExtensionIdentifiers.IsMinPinLength(id) => AssignMinPinLength(ref reader, id, out minPinLength),
                CredentialProtectionPolicyMember => AssignCredentialProtectionPolicy(ref reader, identifier, out credentialProtectionPolicy),
                EnforceCredentialProtectionPolicyMember => AssignEnforceCredentialProtectionPolicy(ref reader, identifier, out enforceCredentialProtectionPolicy),
                _ => throw new Fido2FormatException($"The 'extensions' member '{identifier}' is not recognised.")
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The 'extensions' object is not terminated.");
        }

        Fido2CredProtectRegistrationExtensionInput? credProtect;
        if(credentialProtectionPolicy is not null)
        {
            credProtect = new Fido2CredProtectRegistrationExtensionInput
            {
                CredentialProtectionPolicy = credentialProtectionPolicy,
                EnforceCredentialProtectionPolicy = enforceCredentialProtectionPolicy ?? false
            };
        }
        else if(enforceCredentialProtectionPolicy is not null)
        {
            throw new Fido2FormatException(
                $"The 'extensions' member '{EnforceCredentialProtectionPolicyMember}' requires '{CredentialProtectionPolicyMember}' to be present.");
        }
        else
        {
            credProtect = null;
        }

        return (appIdExclude, largeBlob, minPinLength, credProtect);

        static bool AssignAppIdExclude(ref Utf8JsonReader reader, string identifier, out string? appIdExclude)
        {
            appIdExclude = ReadRequiredString(ref reader, identifier);

            return true;
        }

        static bool AssignLargeBlob(ref Utf8JsonReader reader, out Fido2LargeBlobRegistrationExtensionInput? largeBlob)
        {
            largeBlob = ReadLargeBlobInput(ref reader);

            return true;
        }

        static bool AssignMinPinLength(ref Utf8JsonReader reader, string identifier, out bool? minPinLength)
        {
            minPinLength = ReadRequiredBoolean(ref reader, identifier);

            return true;
        }

        //Assigns the decoded credentialProtectionPolicy value, rejecting any wire value the
        //credProtect registry does not recognise.
        static bool AssignCredentialProtectionPolicy(ref Utf8JsonReader reader, string identifier, out string? credentialProtectionPolicy)
        {
            credentialProtectionPolicy = ReadRequiredString(ref reader, identifier);
            if(!WellKnownCredProtectPolicies.IsRegisteredValue(credentialProtectionPolicy))
            {
                throw new Fido2FormatException($"The 'extensions' member '{identifier}' value '{credentialProtectionPolicy}' is not a registered credentialProtectionPolicy wire value.");
            }

            return true;
        }

        static bool AssignEnforceCredentialProtectionPolicy(ref Utf8JsonReader reader, string identifier, out bool? enforceCredentialProtectionPolicy)
        {
            enforceCredentialProtectionPolicy = ReadRequiredBoolean(ref reader, identifier);

            return true;
        }
    }


    private static Fido2LargeBlobRegistrationExtensionInput ReadLargeBlobInput(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The 'extensions.largeBlob' member MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        LargeBlobSupport? support = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The 'extensions.largeBlob' member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The 'extensions.largeBlob' member '{memberName}' is truncated.");
            }

            if(memberName == SupportMember)
            {
                support = WellKnownLargeBlobSupports.FromWireValue(ReadRequiredString(ref reader, memberName));
            }
            else
            {
                throw new Fido2FormatException($"The 'extensions.largeBlob' member '{memberName}' is not recognised.");
            }
        }

        if(support is null)
        {
            throw new Fido2FormatException("The 'extensions.largeBlob' member 'support' is required.");
        }

        return new Fido2LargeBlobRegistrationExtensionInput { Support = support.Value };
    }


    private static List<string> ReadStringArray(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a JSON array.");
        }

        List<string> values = [];
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.String)
            {
                throw new Fido2FormatException($"An element of the member '{memberName}' MUST be a string.");
            }

            values.Add(reader.GetString()!);
        }

        return values;
    }


    private static string ReadRequiredString(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.String)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a string.");
        }

        return reader.GetString()!;
    }


    private static ReadOnlyMemory<byte> ReadRequiredBinary(ref Utf8JsonReader reader, string memberName)
    {
        string encoded = ReadRequiredString(ref reader, memberName);
        byte[] buffer = new byte[Base64Url.GetMaxDecodedLength(encoded.Length)];
        if(!Base64Url.TryDecodeFromChars(encoded, buffer, out int bytesWritten))
        {
            throw new Fido2FormatException($"The member '{memberName}' is not valid base64url.");
        }

        return bytesWritten == buffer.Length ? buffer : buffer[..bytesWritten];
    }


    private static int ReadRequiredInt32(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.Number)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a number.");
        }

        return reader.GetInt32();
    }


    private static uint ReadRequiredUInt32(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.Number)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a number.");
        }

        return reader.GetUInt32();
    }


    private static bool ReadRequiredBoolean(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.True && reader.TokenType != JsonTokenType.False)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a boolean.");
        }

        return reader.GetBoolean();
    }
}
