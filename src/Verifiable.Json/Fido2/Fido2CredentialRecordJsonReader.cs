using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> reader for the <see cref="Fido2CredentialRecordJsonWriter"/>
/// document shape, reconstructing a <see cref="Fido2CredentialRecord"/> for a subsequent
/// authentication ceremony. Lives beside <see cref="Fido2CredentialRecordJsonWriter"/> for the
/// same reason <see cref="ClientDataJsonReader"/> lives here rather than in
/// <c>Verifiable.Fido2</c>: the FIDO2 library stays serialization-agnostic.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="ClientDataJsonReader"/>/<see cref="MetadataBlobReader"/>, which read
/// spec-defined WIRE formats and therefore skip unrecognised members per those specifications'
/// own forward-compatibility rules, this reader is strict: this document's shape is one this
/// codebase itself defines, so an unrecognised top-level or <c>publicKey</c> sub-object member is
/// rejected rather than silently skipped, as is a repeated member name. Every binary member is
/// decoded as Base64url; a bounded <see cref="Utf8JsonReader"/> nesting depth guards against a
/// maliciously deep document even though this reader's own object/array nesting never exceeds two
/// levels.
/// </para>
/// </remarks>
public static class Fido2CredentialRecordJsonReader
{
    /// <summary>The <c>version</c> member name.</summary>
    private const string VersionMember = "version";

    /// <summary>The <c>type</c> member name.</summary>
    private const string TypeMember = "type";

    /// <summary>The <c>id</c> member name.</summary>
    private const string IdMember = "id";

    /// <summary>The <c>publicKey</c> member name.</summary>
    private const string PublicKeyMember = "publicKey";

    /// <summary>The <c>signCount</c> member name.</summary>
    private const string SignCountMember = "signCount";

    /// <summary>The <c>uvInitialized</c> member name.</summary>
    private const string UvInitializedMember = "uvInitialized";

    /// <summary>The <c>transports</c> member name.</summary>
    private const string TransportsMember = "transports";

    /// <summary>The <c>backupEligible</c> member name.</summary>
    private const string BackupEligibleMember = "backupEligible";

    /// <summary>The <c>backupState</c> member name.</summary>
    private const string BackupStateMember = "backupState";

    /// <summary>
    /// The <c>authenticatorAttachment</c> member name — genuinely OPTIONAL: absent on any document
    /// written before this wave, and on any document a relying party wrote without a reported
    /// <c>authenticatorAttachment</c>. See <see cref="Fido2CredentialRecord.AuthenticatorAttachment"/>.
    /// </summary>
    private const string AuthenticatorAttachmentMember = "authenticatorAttachment";

    /// <summary>The <c>publicKey.kty</c> member name.</summary>
    private const string KtyMember = "kty";

    /// <summary>The <c>publicKey.alg</c> member name.</summary>
    private const string AlgMember = "alg";

    /// <summary>The <c>publicKey.crv</c> member name.</summary>
    private const string CrvMember = "crv";

    /// <summary>The <c>publicKey.x</c> member name.</summary>
    private const string XMember = "x";

    /// <summary>The <c>publicKey.y</c> member name.</summary>
    private const string YMember = "y";

    /// <summary>The <c>publicKey.yCompressionSign</c> member name.</summary>
    private const string YCompressionSignMember = "yCompressionSign";

    /// <summary>The <c>publicKey.n</c> member name (RSA modulus).</summary>
    private const string NMember = "n";

    /// <summary>The <c>publicKey.e</c> member name (RSA public exponent).</summary>
    private const string EMember = "e";


    /// <summary>
    /// Bounds JSON nesting depth. The document never nests more than two levels deep (the
    /// top-level object, and its <c>publicKey</c> sub-object or <c>transports</c> array), so 4 is
    /// generous while still capping recursion depth at parse time for untrusted input.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 4 };


    /// <summary>
    /// Parses a <see cref="Fido2CredentialRecordJsonWriter"/> document into a
    /// <see cref="Fido2CredentialRecord"/>.
    /// </summary>
    /// <param name="document">The raw document bytes.</param>
    /// <param name="pool">The memory pool <see cref="Fido2CredentialRecord.Id"/> rents from.</param>
    /// <returns>The parsed <see cref="Fido2CredentialRecord"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="document"/> is not valid JSON, its top level is not an object, a required
    /// member is missing or has the wrong JSON type, an unrecognised member is present, a member
    /// name repeats (at the top level or within <c>publicKey</c>), a binary member is not valid
    /// base64url, <c>version</c> is not the version this reader supports, or nesting exceeds the
    /// depth bound.
    /// </exception>
    public static Fido2CredentialRecord Read(ReadOnlyMemory<byte> document, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            return ReadObject(document.Span, pool);
        }
        catch(Exception exception) when(exception is JsonException or FormatException or OverflowException)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord document is not well-formed.", exception);
        }
    }


    /// <summary>
    /// Reads the top-level <see cref="Fido2CredentialRecord"/> JSON object.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId created here transfers to the returned Fido2CredentialRecord, which the caller disposes once no longer needed — the CA2000 flag is a false positive.")]
    private static Fido2CredentialRecord ReadObject(ReadOnlySpan<byte> document, MemoryPool<byte> pool)
    {
        Utf8JsonReader reader = new(document, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        int? version = null;
        string? type = null;
        ReadOnlyMemory<byte>? idBytes = null;
        CoseKey? publicKey = null;
        uint? signCount = null;
        bool? uvInitialized = null;
        List<string>? transports = null;
        bool? backupEligible = null;
        bool? backupState = null;
        string? authenticatorAttachment = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' is truncated.");
            }

            switch(memberName)
            {
                case(VersionMember):
                {
                    version = ReadRequiredInt32(ref reader, memberName);
                    break;
                }
                case(TypeMember):
                {
                    type = ReadRequiredString(ref reader, memberName);
                    break;
                }
                case(IdMember):
                {
                    idBytes = ReadRequiredBinary(ref reader, memberName);
                    break;
                }
                case(PublicKeyMember):
                {
                    publicKey = ReadPublicKey(ref reader);
                    break;
                }
                case(SignCountMember):
                {
                    signCount = ReadRequiredUInt32(ref reader, memberName);
                    break;
                }
                case(UvInitializedMember):
                {
                    uvInitialized = ReadRequiredBoolean(ref reader, memberName);
                    break;
                }
                case(TransportsMember):
                {
                    transports = ReadStringArray(ref reader, memberName);
                    break;
                }
                case(BackupEligibleMember):
                {
                    backupEligible = ReadRequiredBoolean(ref reader, memberName);
                    break;
                }
                case(BackupStateMember):
                {
                    backupState = ReadRequiredBoolean(ref reader, memberName);
                    break;
                }
                case(AuthenticatorAttachmentMember):
                {
                    authenticatorAttachment = ReadRequiredString(ref reader, memberName);
                    break;
                }
                default:
                {
                    throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' is not recognised.");
                }
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord object is not terminated.");
        }

        if(reader.Read())
        {
            throw new Fido2FormatException("The Fido2CredentialRecord document carries content trailing its closing brace.");
        }

        if(version is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'version' is required.");
        }

        if(version.Value != Fido2CredentialRecordJsonWriter.CurrentVersion)
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member 'version' value {version.Value} is not supported; expected {Fido2CredentialRecordJsonWriter.CurrentVersion}.");
        }

        if(type is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'type' is required.");
        }

        if(idBytes is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'id' is required.");
        }

        if(publicKey is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'publicKey' is required.");
        }

        if(signCount is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'signCount' is required.");
        }

        if(uvInitialized is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'uvInitialized' is required.");
        }

        if(transports is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'transports' is required.");
        }

        if(backupEligible is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'backupEligible' is required.");
        }

        if(backupState is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'backupState' is required.");
        }

        CredentialId id = CredentialId.Create(idBytes.Value.Span, pool);

        return new Fido2CredentialRecord(
            type,
            id,
            publicKey,
            signCount.Value,
            uvInitialized.Value,
            transports,
            backupEligible.Value,
            backupState.Value,
            authenticatorAttachment);
    }


    /// <summary>
    /// Reads the <c>publicKey</c> sub-object into a <see cref="CoseKey"/>, requiring <c>kty</c> and
    /// rejecting an unrecognised or repeated member.
    /// </summary>
    private static CoseKey ReadPublicKey(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord member 'publicKey' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        int? kty = null;
        int? alg = null;
        int? curve = null;
        ReadOnlyMemory<byte>? x = null;
        ReadOnlyMemory<byte>? y = null;
        bool? encodedYCompressionSign = null;
        ReadOnlyMemory<byte>? n = null;
        ReadOnlyMemory<byte>? e = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The Fido2CredentialRecord 'publicKey' member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The Fido2CredentialRecord 'publicKey' member '{memberName}' is truncated.");
            }

            switch(memberName)
            {
                case(KtyMember):
                {
                    kty = ReadRequiredInt32(ref reader, memberName);
                    break;
                }
                case(AlgMember):
                {
                    alg = ReadRequiredInt32(ref reader, memberName);
                    break;
                }
                case(CrvMember):
                {
                    curve = ReadRequiredInt32(ref reader, memberName);
                    break;
                }
                case(XMember):
                {
                    x = ReadRequiredBinary(ref reader, memberName);
                    break;
                }
                case(YMember):
                {
                    y = ReadRequiredBinary(ref reader, memberName);
                    break;
                }
                case(YCompressionSignMember):
                {
                    encodedYCompressionSign = ReadRequiredBoolean(ref reader, memberName);
                    break;
                }
                case(NMember):
                {
                    n = ReadRequiredBinary(ref reader, memberName);
                    break;
                }
                case(EMember):
                {
                    e = ReadRequiredBinary(ref reader, memberName);
                    break;
                }
                default:
                {
                    throw new Fido2FormatException($"The Fido2CredentialRecord 'publicKey' member '{memberName}' is not recognised.");
                }
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord 'publicKey' object is not terminated.");
        }

        if(kty is null)
        {
            throw new Fido2FormatException("The Fido2CredentialRecord 'publicKey' member 'kty' is required.");
        }

        return new CoseKey(kty.Value, alg, curve, x, y, encodedYCompressionSign, n, e);
    }


    /// <summary>
    /// Reads a JSON array of strings — the <c>transports</c> shape.
    /// </summary>
    private static List<string> ReadStringArray(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' MUST be a JSON array.");
        }

        List<string> values = new();
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.String)
            {
                throw new Fido2FormatException($"An element of the Fido2CredentialRecord member '{memberName}' MUST be a string.");
            }

            values.Add(reader.GetString()!);
        }

        if(reader.TokenType != JsonTokenType.EndArray)
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' array is not terminated.");
        }

        return values;
    }


    /// <summary>
    /// Reads the reader's current value as a string, naming <paramref name="memberName"/> in the
    /// rejection when the value is not string-shaped.
    /// </summary>
    private static string ReadRequiredString(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.String)
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' MUST be a string.");
        }

        return reader.GetString()!;
    }


    /// <summary>
    /// Reads the reader's current value as a base64url string, decoding it, naming
    /// <paramref name="memberName"/> in the rejection when the value is not string-shaped or not
    /// valid base64url.
    /// </summary>
    private static ReadOnlyMemory<byte> ReadRequiredBinary(ref Utf8JsonReader reader, string memberName)
    {
        string encoded = ReadRequiredString(ref reader, memberName);
        byte[] buffer = new byte[Base64Url.GetMaxDecodedLength(encoded.Length)];
        if(!Base64Url.TryDecodeFromChars(encoded, buffer, out int bytesWritten))
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' is not valid base64url.");
        }

        return bytesWritten == buffer.Length ? buffer : buffer[..bytesWritten];
    }


    /// <summary>
    /// Reads the reader's current value as a 32-bit integer, naming <paramref name="memberName"/>
    /// in the rejection when the value is not number-shaped.
    /// </summary>
    private static int ReadRequiredInt32(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.Number)
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' MUST be a number.");
        }

        return reader.GetInt32();
    }


    /// <summary>
    /// Reads the reader's current value as an unsigned 32-bit integer, naming
    /// <paramref name="memberName"/> in the rejection when the value is not number-shaped.
    /// </summary>
    private static uint ReadRequiredUInt32(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.Number)
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' MUST be a number.");
        }

        return reader.GetUInt32();
    }


    /// <summary>
    /// Reads the reader's current value as a boolean, naming <paramref name="memberName"/> in the
    /// rejection when the value is not boolean-shaped.
    /// </summary>
    private static bool ReadRequiredBoolean(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.True && reader.TokenType != JsonTokenType.False)
        {
            throw new Fido2FormatException($"The Fido2CredentialRecord member '{memberName}' MUST be a boolean.");
        }

        return reader.GetBoolean();
    }
}
