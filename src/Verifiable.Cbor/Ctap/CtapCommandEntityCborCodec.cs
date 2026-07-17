using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// Shared CTAP2-canonical CBOR codec helpers for the nested, text-string-keyed entity structures that
/// <c>authenticatorMakeCredential</c> and <c>authenticatorGetAssertion</c>'s request and response maps
/// both carry: <c>rp</c>, <c>user</c>, <c>PublicKeyCredentialDescriptor</c> (<c>excludeList</c>,
/// <c>allowList</c>, and the assertion response's <c>credential</c>), <c>PublicKeyCredentialParameters</c>
/// (<c>pubKeyCredParams</c>), and the <c>options</c> map.
/// </summary>
/// <remarks>
/// <para>
/// Every nested map is written in already-ascending canonical key order (shorter-key-first, then
/// bytewise lexical for equal-length keys) so no run-time sort is needed to reach the CTAP2 canonical
/// CBOR encoding form — mirroring <c>Verifiable.Cbor.Ctap.CtapGetInfoResponseCborWriter</c>'s own
/// convention. <see cref="CborConformanceMode.Ctap2Canonical"/> validates this order (and rejects
/// duplicate keys and indefinite-length collections) independently at read time, so a caller-side
/// ordering mistake here would surface as a <see cref="CborContentException"/> rather than silently
/// producing non-canonical bytes.
/// </para>
/// <para>
/// Every reader here tolerates an unrecognized map member by skipping it, per CTAP 2.3 section 8's
/// forward-compatibility rule ("If map keys are present that an implementation does not understand,
/// they MUST be ignored"). None of these helpers catch or wrap <see cref="CborContentException"/>,
/// <see cref="InvalidOperationException"/>, or <see cref="OverflowException"/> — the eight public
/// command codec entry points that call them own that responsibility, wrapping into
/// <see cref="Fido2FormatException"/> at their own boundary. Every "missing required member" throw a
/// reader here raises directly is classified <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>
/// — a nested structure's own shape failing, distinct from the outer bytes failing to parse at all —
/// and, since <see cref="Fido2FormatException"/> is none of the three BCL types the calling boundary's
/// own catch rewraps, it propagates through unchanged.
/// </para>
/// </remarks>
internal static class CtapCommandEntityCborCodec
{
    /// <summary>The <c>rp</c>/<c>user</c> entity's <c>id</c> member key.</summary>
    private const string IdKey = "id";

    /// <summary>The <c>rp</c>/<c>user</c> entity's <c>name</c> member key.</summary>
    private const string NameKey = "name";

    /// <summary>The <c>user</c> entity's <c>displayName</c> member key.</summary>
    private const string DisplayNameKey = "displayName";

    /// <summary>The <c>PublicKeyCredentialDescriptor</c>'s <c>type</c> member key.</summary>
    private const string TypeKey = "type";

    /// <summary>The <c>PublicKeyCredentialDescriptor</c>'s <c>transports</c> member key.</summary>
    private const string TransportsKey = "transports";

    /// <summary>The <c>PublicKeyCredentialParameters</c>'s <c>alg</c> member key.</summary>
    private const string AlgKey = "alg";


    /// <summary>
    /// Writes a <c>PublicKeyCredentialRpEntity</c> map: <c>id</c> (required text string), then
    /// <c>name</c> (optional text string) if present.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the map's key.</param>
    /// <param name="rp">The relying party entity to write.</param>
    public static void WriteRpEntity(CborWriter writer, CtapPublicKeyCredentialRpEntity rp)
    {
        int memberCount = 1 + (rp.Name is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteTextString(IdKey);
        writer.WriteTextString(rp.Id);

        if(rp.Name is string name)
        {
            writer.WriteTextString(NameKey);
            writer.WriteTextString(name);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads a <c>PublicKeyCredentialRpEntity</c> map.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the map.</param>
    /// <returns>The decoded relying party entity.</returns>
    /// <exception cref="Fido2FormatException">The map omits the required <c>id</c> member.</exception>
    public static CtapPublicKeyCredentialRpEntity ReadRpEntity(CborReader reader)
    {
        int? count = reader.ReadStartMap();
        string? id = null;
        string? name = null;

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            string key = reader.ReadTextString();
            read++;

            _ = key switch
            {
                IdKey => id = reader.ReadTextString(),
                NameKey => name = reader.ReadTextString(),
                _ => SkipValue(reader)
            };
        }

        reader.ReadEndMap();

        if(id is null)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The rp entity is missing the required 'id' member.");
        }

        return new CtapPublicKeyCredentialRpEntity(id, name);

        //Skips an unrecognized member's value; unknown members are tolerated.
        static string? SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return null;
        }
    }


    /// <summary>
    /// Writes a <c>PublicKeyCredentialUserEntity</c> map: <c>id</c> (required byte string), then
    /// <c>name</c> and <c>displayName</c> (optional text strings) if present.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the map's key.</param>
    /// <param name="user">The user entity to write.</param>
    public static void WriteUserEntity(CborWriter writer, CtapPublicKeyCredentialUserEntity user)
    {
        int memberCount = 1 + (user.Name is not null ? 1 : 0) + (user.DisplayName is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteTextString(IdKey);
        writer.WriteByteString(user.Id.AsReadOnlySpan());

        if(user.Name is string name)
        {
            writer.WriteTextString(NameKey);
            writer.WriteTextString(name);
        }

        if(user.DisplayName is string displayName)
        {
            writer.WriteTextString(DisplayNameKey);
            writer.WriteTextString(displayName);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads a <c>PublicKeyCredentialUserEntity</c> map.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the map.</param>
    /// <param name="pool">The memory pool the returned entity's user handle rents from.</param>
    /// <returns>The decoded user entity.</returns>
    /// <exception cref="Fido2FormatException">The map omits the required <c>id</c> member.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the UserHandle created here transfers to the returned entity, which the caller (and, transitively, the request/response model it decorates) disposes — the CA2000 flag is a false positive, mirroring Fido2CredentialRecordJsonReader's identical CredentialId.Create suppression.")]
    public static CtapPublicKeyCredentialUserEntity ReadUserEntity(CborReader reader, MemoryPool<byte> pool)
    {
        int? count = reader.ReadStartMap();
        byte[]? idBytes = null;
        string? name = null;
        string? displayName = null;

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            string key = reader.ReadTextString();
            read++;

            switch(key)
            {
                case(IdKey):
                {
                    idBytes = reader.ReadByteString();
                    break;
                }
                case(NameKey):
                {
                    name = reader.ReadTextString();
                    break;
                }
                case(DisplayNameKey):
                {
                    displayName = reader.ReadTextString();
                    break;
                }
                default:
                {
                    reader.SkipValue();
                    break;
                }
            }
        }

        reader.ReadEndMap();

        if(idBytes is null)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The user entity is missing the required 'id' member.");
        }

        //UserHandle.Create is deferred to this final, non-throwing-afterward step (the pooled carrier
        //is constructed only once every other member has decoded successfully) so no disposal-on-failure
        //path is needed here — mirrors the "construct-and-return" shape the codebase's own disposal
        //analysis recognizes as leak-free.
        return new CtapPublicKeyCredentialUserEntity(UserHandle.Create(idBytes, pool), name, displayName);
    }


    /// <summary>
    /// Writes a <c>PublicKeyCredentialDescriptor</c> map: <c>id</c> (required byte string), <c>type</c>
    /// (required text string), then <c>transports</c> (optional array of text strings) if present.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the map's key.</param>
    /// <param name="descriptor">The credential descriptor to write.</param>
    public static void WriteDescriptor(CborWriter writer, PublicKeyCredentialDescriptor descriptor)
    {
        int memberCount = 2 + (descriptor.Transports is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteTextString(IdKey);
        writer.WriteByteString(descriptor.Id.AsReadOnlySpan());

        writer.WriteTextString(TypeKey);
        writer.WriteTextString(descriptor.Type);

        if(descriptor.Transports is IReadOnlyList<string> transports)
        {
            writer.WriteTextString(TransportsKey);
            WriteStringArray(writer, transports);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads a <c>PublicKeyCredentialDescriptor</c> map.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the map.</param>
    /// <param name="pool">The memory pool the returned descriptor's credential identifier rents from.</param>
    /// <returns>The decoded credential descriptor.</returns>
    /// <exception cref="Fido2FormatException">The map omits a required member.</exception>
    public static PublicKeyCredentialDescriptor ReadDescriptor(CborReader reader, MemoryPool<byte> pool)
    {
        int? count = reader.ReadStartMap();
        byte[]? idBytes = null;
        string? type = null;
        List<string>? transports = null;

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            string key = reader.ReadTextString();
            read++;

            switch(key)
            {
                case(IdKey):
                {
                    idBytes = reader.ReadByteString();
                    break;
                }
                case(TypeKey):
                {
                    type = reader.ReadTextString();
                    break;
                }
                case(TransportsKey):
                {
                    transports = ReadStringArray(reader);
                    break;
                }
                default:
                {
                    reader.SkipValue();
                    break;
                }
            }
        }

        reader.ReadEndMap();

        if(idBytes is null)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The credential descriptor is missing the required 'id' member.");
        }

        if(type is null)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The credential descriptor is missing the required 'type' member.");
        }

        //CredentialId.Create is deferred to this final, non-throwing-afterward step — see the identical
        //rationale on ReadUserEntity.
        return new PublicKeyCredentialDescriptor
        {
            Type = type,
            Id = CredentialId.Create(idBytes, pool),
            Transports = transports
        };
    }


    /// <summary>
    /// Writes a <c>PublicKeyCredentialParameters</c> map: <c>alg</c> (required integer), then
    /// <c>type</c> (required text string).
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the map's key.</param>
    /// <param name="parameters">The credential parameters to write.</param>
    public static void WriteParameters(CborWriter writer, PublicKeyCredentialParameters parameters)
    {
        writer.WriteStartMap(2);

        writer.WriteTextString(AlgKey);
        writer.WriteInt32(parameters.Alg);

        writer.WriteTextString(TypeKey);
        writer.WriteTextString(parameters.Type);

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads a <c>PublicKeyCredentialParameters</c> map.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the map.</param>
    /// <returns>The decoded credential parameters.</returns>
    /// <exception cref="Fido2FormatException">The map omits a required member.</exception>
    public static PublicKeyCredentialParameters ReadParameters(CborReader reader)
    {
        int? count = reader.ReadStartMap();
        int? alg = null;
        string? type = null;

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            string key = reader.ReadTextString();
            read++;

            switch(key)
            {
                case(AlgKey):
                {
                    alg = checked((int)reader.ReadInt64());
                    break;
                }
                case(TypeKey):
                {
                    type = reader.ReadTextString();
                    break;
                }
                default:
                {
                    reader.SkipValue();
                    break;
                }
            }
        }

        reader.ReadEndMap();

        if(alg is null)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The credential parameters entry is missing the required 'alg' member.");
        }

        if(type is null)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The credential parameters entry is missing the required 'type' member.");
        }

        return new PublicKeyCredentialParameters
        {
            Type = type,
            Alg = alg.Value
        };
    }


    /// <summary>
    /// Writes the <c>options</c> map: whichever of <c>rk</c>, <c>up</c>, <c>uv</c> the model carries a
    /// value for, in canonical key order (<c>rk</c> before <c>up</c> before <c>uv</c> — all three keys
    /// share a two-character length, so the tie-break is bytewise lexical).
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the map's key.</param>
    /// <param name="options">The option values to write.</param>
    public static void WriteOptions(CborWriter writer, CtapCommandOptions options)
    {
        int memberCount = (options.ResidentKey.HasValue ? 1 : 0)
            + (options.UserPresence.HasValue ? 1 : 0)
            + (options.UserVerification.HasValue ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(options.ResidentKey is bool residentKey)
        {
            writer.WriteTextString(WellKnownCtapRequestOptionIds.Rk);
            writer.WriteBoolean(residentKey);
        }

        if(options.UserPresence is bool userPresence)
        {
            writer.WriteTextString(WellKnownCtapRequestOptionIds.Up);
            writer.WriteBoolean(userPresence);
        }

        if(options.UserVerification is bool userVerification)
        {
            writer.WriteTextString(WellKnownCtapRequestOptionIds.Uv);
            writer.WriteBoolean(userVerification);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Reads the <c>options</c> map, tolerating any option key beyond <c>rk</c>/<c>up</c>/<c>uv</c>.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the map.</param>
    /// <returns>The decoded option values.</returns>
    public static CtapCommandOptions ReadOptions(CborReader reader)
    {
        int? count = reader.ReadStartMap();
        bool? residentKey = null;
        bool? userPresence = null;
        bool? userVerification = null;

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            string optionId = reader.ReadTextString();
            bool value = reader.ReadBoolean();
            read++;

            _ = optionId switch
            {
                var id when WellKnownCtapRequestOptionIds.IsRk(id) => residentKey = value,
                var id when WellKnownCtapRequestOptionIds.IsUp(id) => userPresence = value,
                var id when WellKnownCtapRequestOptionIds.IsUv(id) => userVerification = value,
                _ => value
            };
        }

        reader.ReadEndMap();

        return new CtapCommandOptions(residentKey, userPresence, userVerification);
    }


    /// <summary>
    /// Writes a definite-length CBOR array of text strings.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the array.</param>
    /// <param name="values">The text values to write.</param>
    public static void WriteStringArray(CborWriter writer, IReadOnlyList<string> values)
    {
        writer.WriteStartArray(values.Count);
        foreach(string value in values)
        {
            writer.WriteTextString(value);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads a definite-length CBOR array of text strings.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the array.</param>
    /// <returns>The decoded text values, in wire order.</returns>
    public static List<string> ReadStringArray(CborReader reader)
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


    /// <summary>
    /// Writes a definite-length CBOR array of <c>PublicKeyCredentialDescriptor</c> maps.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the array.</param>
    /// <param name="descriptors">The descriptors to write, in wire order.</param>
    public static void WriteDescriptorArray(CborWriter writer, IReadOnlyList<PublicKeyCredentialDescriptor> descriptors)
    {
        writer.WriteStartArray(descriptors.Count);
        foreach(PublicKeyCredentialDescriptor descriptor in descriptors)
        {
            WriteDescriptor(writer, descriptor);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads a definite-length CBOR array of <c>PublicKeyCredentialDescriptor</c> maps.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the array.</param>
    /// <param name="pool">The memory pool each descriptor's credential identifier rents from.</param>
    /// <returns>The decoded descriptors, in wire order.</returns>
    public static List<PublicKeyCredentialDescriptor> ReadDescriptorArray(CborReader reader, MemoryPool<byte> pool)
    {
        int? count = reader.ReadStartArray();
        var descriptors = new List<PublicKeyCredentialDescriptor>();

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndArray : read < count.Value)
        {
            descriptors.Add(ReadDescriptor(reader, pool));
            read++;
        }

        reader.ReadEndArray();

        return descriptors;
    }


    /// <summary>
    /// Writes a definite-length CBOR array of <c>PublicKeyCredentialParameters</c> maps.
    /// </summary>
    /// <param name="writer">The CBOR writer positioned to write the array.</param>
    /// <param name="parametersList">The parameters to write, in wire (most-to-least-preferred) order.</param>
    public static void WriteParametersArray(CborWriter writer, IReadOnlyList<PublicKeyCredentialParameters> parametersList)
    {
        writer.WriteStartArray(parametersList.Count);
        foreach(PublicKeyCredentialParameters parameters in parametersList)
        {
            WriteParameters(writer, parameters);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads a definite-length CBOR array of <c>PublicKeyCredentialParameters</c> maps.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the array.</param>
    /// <returns>The decoded parameters, in wire (most-to-least-preferred) order.</returns>
    public static List<PublicKeyCredentialParameters> ReadParametersArray(CborReader reader)
    {
        int? count = reader.ReadStartArray();
        var parametersList = new List<PublicKeyCredentialParameters>();

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndArray : read < count.Value)
        {
            parametersList.Add(ReadParameters(reader));
            read++;
        }

        reader.ReadEndArray();

        return parametersList;
    }
}
