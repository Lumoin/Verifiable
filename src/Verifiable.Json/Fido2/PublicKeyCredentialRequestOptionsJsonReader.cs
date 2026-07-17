using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> reader for the <see cref="PublicKeyCredentialRequestOptionsJsonWriter"/>
/// document shape, reconstructing a <see cref="PublicKeyCredentialRequestOptions"/> — for CLI/test
/// round-trip, since the CR's own <c>parseRequestOptionsFromJSON()</c> is a client (browser)
/// operation this library does not itself perform.
/// </summary>
/// <remarks>
/// Strict, mirroring <see cref="PublicKeyCredentialCreationOptionsJsonReader"/>'s posture — see that
/// type's remarks.
/// </remarks>
public static class PublicKeyCredentialRequestOptionsJsonReader
{
    private const string ChallengeMember = "challenge";
    private const string TimeoutMember = "timeout";
    private const string RpIdMember = "rpId";
    private const string AllowCredentialsMember = "allowCredentials";
    private const string TypeMember = "type";
    private const string IdMember = "id";
    private const string TransportsMember = "transports";
    private const string UserVerificationMember = "userVerification";
    private const string HintsMember = "hints";
    private const string ExtensionsMember = "extensions";
    private const string ReadMember = "read";
    private const string WriteMember = "write";


    /// <summary>
    /// Bounds JSON nesting depth. The deepest legal path is <c>allowCredentials[].transports[]</c> or
    /// <c>extensions.largeBlob.write</c> (three levels below the top object), so 6 is generous while
    /// still capping recursion depth at parse time.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 6 };


    /// <summary>
    /// Parses a <see cref="PublicKeyCredentialRequestOptionsJsonWriter"/> document into a
    /// <see cref="PublicKeyCredentialRequestOptions"/>.
    /// </summary>
    /// <param name="document">The raw document bytes.</param>
    /// <param name="pool">The memory pool descriptor <c>id</c> carriers and a <c>largeBlob.write</c> payload rent from.</param>
    /// <returns>The parsed <see cref="PublicKeyCredentialRequestOptions"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="document"/> is not valid JSON, its top level is not an object, a required
    /// member is missing or has the wrong JSON type, an unrecognised member is present, a member name
    /// repeats, a binary member is not valid base64url, an enum-backed member's wire value is not
    /// registered, or nesting exceeds the depth bound.
    /// </exception>
    public static PublicKeyCredentialRequestOptions Read(ReadOnlyMemory<byte> document, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            return ReadObject(document.Span, pool);
        }
        catch(Exception exception) when(exception is JsonException or FormatException or OverflowException or ArgumentOutOfRangeException)
        {
            throw new Fido2FormatException("The PublicKeyCredentialRequestOptions document is not well-formed.", exception);
        }
    }


    private static PublicKeyCredentialRequestOptions ReadObject(ReadOnlySpan<byte> document, MemoryPool<byte> pool)
    {
        Utf8JsonReader reader = new(document, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialRequestOptions top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? challenge = null;
        uint? timeout = null;
        string? rpId = null;
        List<PublicKeyCredentialDescriptor>? allowCredentials = null;
        UserVerificationRequirement? userVerification = null;
        List<PublicKeyCredentialHint>? hints = null;
        string? appId = null;
        Fido2LargeBlobAssertionExtensionInput? largeBlob = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The PublicKeyCredentialRequestOptions member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The PublicKeyCredentialRequestOptions member '{memberName}' is truncated.");
            }

            switch(memberName)
            {
                case(ChallengeMember):
                {
                    challenge = ReadRequiredString(ref reader, memberName);
                    break;
                }
                case(TimeoutMember):
                {
                    timeout = ReadRequiredUInt32(ref reader, memberName);
                    break;
                }
                case(RpIdMember):
                {
                    rpId = ReadRequiredString(ref reader, memberName);
                    break;
                }
                case(AllowCredentialsMember):
                {
                    allowCredentials = ReadDescriptors(ref reader, memberName, pool);
                    break;
                }
                case(UserVerificationMember):
                {
                    userVerification = WellKnownUserVerificationRequirements.FromWireValue(ReadRequiredString(ref reader, memberName));
                    break;
                }
                case(HintsMember):
                {
                    hints = ReadHints(ref reader, memberName);
                    break;
                }
                case(ExtensionsMember):
                {
                    (appId, largeBlob) = ReadExtensions(ref reader);
                    break;
                }
                default:
                {
                    throw new Fido2FormatException($"The PublicKeyCredentialRequestOptions member '{memberName}' is not recognised.");
                }
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialRequestOptions object is not terminated.");
        }

        if(reader.Read())
        {
            throw new Fido2FormatException("The PublicKeyCredentialRequestOptions document carries content trailing its closing brace.");
        }

        if(challenge is null)
        {
            throw new Fido2FormatException("The PublicKeyCredentialRequestOptions member 'challenge' is required.");
        }

        return new PublicKeyCredentialRequestOptions
        {
            Challenge = challenge,
            Timeout = timeout,
            RpId = rpId,
            AllowCredentials = allowCredentials,
            UserVerification = userVerification,
            Hints = hints,
            AppId = appId,
            LargeBlob = largeBlob
        };
    }


    private static List<PublicKeyCredentialDescriptor> ReadDescriptors(ref Utf8JsonReader reader, string memberName, MemoryPool<byte> pool)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException($"The PublicKeyCredentialRequestOptions member '{memberName}' MUST be a JSON array.");
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

                switch(elementMemberName)
                {
                    case(TypeMember):
                    {
                        type = ReadRequiredString(ref reader, elementMemberName);
                        break;
                    }
                    case(IdMember):
                    {
                        idBytes = ReadRequiredBinary(ref reader, elementMemberName);
                        break;
                    }
                    case(TransportsMember):
                    {
                        transports = ReadStringArray(ref reader, elementMemberName);
                        break;
                    }
                    default:
                    {
                        throw new Fido2FormatException($"A '{memberName}' element member '{elementMemberName}' is not recognised.");
                    }
                }
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


    private static (string? AppId, Fido2LargeBlobAssertionExtensionInput? LargeBlob) ReadExtensions(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The PublicKeyCredentialRequestOptions member 'extensions' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? appId = null;
        Fido2LargeBlobAssertionExtensionInput? largeBlob = null;

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

            //WellKnownWebAuthnExtensionIdentifiers members are static readonly interned strings (so
            //IsXxx's ReferenceEquals fast path applies), not const, so this is a guarded switch over
            //a pattern variable rather than constant case labels.
            switch(identifier)
            {
                case var name when WellKnownWebAuthnExtensionIdentifiers.IsAppId(name):
                {
                    appId = ReadRequiredString(ref reader, identifier);
                    break;
                }
                case var name when WellKnownWebAuthnExtensionIdentifiers.IsLargeBlob(name):
                {
                    largeBlob = ReadLargeBlobInput(ref reader);
                    break;
                }
                default:
                {
                    throw new Fido2FormatException($"The 'extensions' member '{identifier}' is not recognised.");
                }
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The 'extensions' object is not terminated.");
        }

        return (appId, largeBlob);
    }


    private static Fido2LargeBlobAssertionExtensionInput ReadLargeBlobInput(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The 'extensions.largeBlob' member MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        bool? read = null;
        ReadOnlyMemory<byte>? writeBytes = null;

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

            switch(memberName)
            {
                case(ReadMember):
                {
                    read = ReadRequiredBoolean(ref reader, memberName);
                    break;
                }
                case(WriteMember):
                {
                    writeBytes = ReadRequiredBinary(ref reader, memberName);
                    break;
                }
                default:
                {
                    throw new Fido2FormatException($"The 'extensions.largeBlob' member '{memberName}' is not recognised.");
                }
            }
        }

        if(read is not null && writeBytes is not null)
        {
            throw new Fido2FormatException("The 'extensions.largeBlob' member cannot carry both 'read' and 'write'.");
        }

        if(writeBytes is not null)
        {
            //Not pooled: TaggedMemory<byte> wraps the plain array ReadRequiredBinary already
            //allocated, matching this carrier's "wrap, don't copy into pooled memory" convention.
            return Fido2LargeBlobAssertionExtensionInput.ForWrite(new TaggedMemory<byte>(writeBytes.Value, Fido2BufferTags.LargeBlob));
        }

        if(read is true)
        {
            return Fido2LargeBlobAssertionExtensionInput.ForRead();
        }

        throw new Fido2FormatException("The 'extensions.largeBlob' member requires exactly one of 'read' or 'write'.");
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
