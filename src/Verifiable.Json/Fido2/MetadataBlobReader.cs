using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> reader for a FIDO Metadata Service BLOB's raw compact-JWS
/// bytes — the shipped default for <see cref="ParseMetadataBlobDelegate"/>. Its <see cref="Read"/>
/// method matches that delegate's shape exactly, so it can be assigned directly:
/// <c>ParseMetadataBlobDelegate d = MetadataBlobReader.Read;</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7: Metadata BLOB</see> defines the BLOB as a three-segment
/// compact JWS: <c>EncodedJWTHeader | "." | EncodedMetadataBLOBPayload | "." | EncodedJWSSignature</c>,
/// each segment base64url encoded without padding. The JWT Header's own <c>x5c</c> member (RFC 7515
/// §4.1.6), by contrast, is an array of STANDARD base64 strings WITH padding — mixing the two
/// decoders is a documented pitfall this reader avoids by construction: the envelope segments go
/// through <see cref="Base64Url"/>, the header's <c>x5c</c> entries through
/// <see cref="Convert.FromBase64String(string)"/>.
/// </para>
/// <para>
/// Reads directly off a <see cref="Utf8JsonReader"/> positioned over each decoded segment — no
/// intermediate <see cref="JsonDocument"/> buffering. <c>MaxDepth</c> is 16, deeper than
/// <c>ClientDataJsonReader</c>'s 8, because a metadata statement's nested arrays-of-objects
/// (<c>userVerificationDetails</c>, <c>tcDisplayPNGCharacteristics</c>, and similar) run deeper than
/// the flat <c>CollectedClientData</c> object. Only <c>x5c</c> is required from the JWT Header; an
/// <c>x5u</c> header is rejected outright — fetching a certificate chain by URL is fetcher-territory
/// this zero-HTTP library does not perform, documented as out of scope rather than silently ignored.
/// Only <c>entries</c>/<c>statusReports</c>/<c>metadataStatement.attestationRootCertificates</c> are
/// typed from the payload; every other <c>metadataStatement</c> member is left in the raw slice
/// <see cref="MetadataBlobPayloadEntry.RawMetadataStatement"/> carries. Unknown top-level members
/// are skipped (forward-compatible), duplicate members are rejected, and an entry's <c>aaguid</c> is
/// parsed strictly as a canonical (dashed, unbraced) GUID string.
/// </para>
/// </remarks>
public static class MetadataBlobReader
{
    /// <summary>The <c>attestationRootCertificates</c> member name within a <c>metadataStatement</c> object.</summary>
    private const string AttestationRootCertificatesMember = "attestationRootCertificates";

    /// <summary>The <c>legalHeader</c> member name within a Metadata BLOB payload.</summary>
    private const string LegalHeaderMember = "legalHeader";

    /// <summary>The <c>no</c> member name within a Metadata BLOB payload.</summary>
    private const string NoMember = "no";

    /// <summary>The <c>nextUpdate</c> member name within a Metadata BLOB payload.</summary>
    private const string NextUpdateMember = "nextUpdate";

    /// <summary>The <c>entries</c> member name within a Metadata BLOB payload.</summary>
    private const string EntriesMember = "entries";

    /// <summary>The <c>aaid</c> member name within a Metadata BLOB payload entry.</summary>
    private const string AaidMember = "aaid";

    /// <summary>The <c>aaguid</c> member name within a Metadata BLOB payload entry.</summary>
    private const string AaguidMember = "aaguid";

    /// <summary>The <c>attestationCertificateKeyIdentifiers</c> member name within a Metadata BLOB payload entry.</summary>
    private const string AttestationCertificateKeyIdentifiersMember = "attestationCertificateKeyIdentifiers";

    /// <summary>The <c>metadataStatement</c> member name within a Metadata BLOB payload entry.</summary>
    private const string MetadataStatementMember = "metadataStatement";

    /// <summary>The <c>statusReports</c> member name within a Metadata BLOB payload entry.</summary>
    private const string StatusReportsMember = "statusReports";

    /// <summary>The <c>timeOfLastStatusChange</c> member name within a Metadata BLOB payload entry.</summary>
    private const string TimeOfLastStatusChangeMember = "timeOfLastStatusChange";

    /// <summary>The <c>status</c> member name within a status report.</summary>
    private const string StatusMember = "status";

    /// <summary>The <c>effectiveDate</c> member name within a status report.</summary>
    private const string EffectiveDateMember = "effectiveDate";

    /// <summary>The <c>certificate</c> member name within a status report.</summary>
    private const string CertificateMember = "certificate";

    /// <summary>The ISO-8601 simple date format every Metadata BLOB date-shaped member uses.</summary>
    private const string DateFormat = "yyyy-MM-dd";

    /// <summary>The canonical dashed, unbraced GUID format an <c>aaguid</c> member is parsed with.</summary>
    private const string CanonicalGuidFormat = "D";


    /// <summary>
    /// Bounds JSON nesting depth for untrusted, wire-received BLOB header/payload segments. See the
    /// type-level remarks for why this is deeper than <c>ClientDataJsonReader</c>'s bound.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 16 };


    /// <summary>
    /// Parses a Metadata BLOB's raw compact-JWS bytes into an <see cref="UnverifiedMetadataBlob"/>.
    /// Matches <see cref="ParseMetadataBlobDelegate"/>.
    /// </summary>
    /// <param name="blobBytes">The raw compact-JWS bytes, exactly as the caller obtained them.</param>
    /// <param name="pool">The memory pool the decoded certificate carriers rent from.</param>
    /// <returns>The decoded, unverified <see cref="UnverifiedMetadataBlob"/>.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="blobBytes"/> is not a well-formed three-segment compact JWS, either segment is
    /// not valid base64url, the header is not a JSON object missing/malformed <c>alg</c>/<c>x5c</c> or
    /// carries an <c>x5u</c> member, the payload is not a JSON object with the required
    /// <c>no</c>/<c>nextUpdate</c>/<c>entries</c> members, an entry is missing its required
    /// <c>metadataStatement</c>/<c>statusReports</c> or sets none of <c>aaid</c>/<c>aaguid</c>/
    /// <c>attestationCertificateKeyIdentifiers</c>, a status report is missing its required
    /// <c>status</c>, an <c>aaguid</c> is not a canonical GUID string, a date-shaped member is not
    /// ISO-8601, a modeled member carries an explicit JSON <c>null</c> or an empty DOMString, an
    /// <c>attestationCertificateKeyIdentifiers</c> element is empty, non-hex, or upper-case hex, an
    /// <c>x5c</c>/<c>attestationCertificateKeyIdentifiers</c> array is present but empty, a top-level
    /// member repeats, or nesting exceeds the depth bound.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned UnverifiedMetadataBlob (and the UnverifiedMetadataBlobPayload it wraps) transfers to the caller, who disposes it once no longer needed — the CA2000 flag on ReadPayload's return is a false positive since that return value's ownership passes straight into the constructed UnverifiedMetadataBlob.")]
    public static UnverifiedMetadataBlob Read(ReadOnlyMemory<byte> blobBytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        (int firstDot, int secondDot) = LocateSegments(blobBytes.Span);
        ReadOnlyMemory<byte> headerSegment = blobBytes[..firstDot];
        ReadOnlyMemory<byte> payloadSegment = blobBytes[(firstDot + 1)..secondDot];
        ReadOnlyMemory<byte> signatureSegment = blobBytes[(secondDot + 1)..];

        List<PkiCertificateMemory>? x5c = null;
        try
        {
            string algorithm = ReadHeader(headerSegment.Span, pool, out x5c);

            UnverifiedMetadataBlobPayload payload;
            using(IMemoryOwner<byte> payloadBufferOwner = DecodeBase64UrlToPooledBuffer(payloadSegment.Span, pool, out int payloadLength))
            {
                payload = ReadPayload(payloadBufferOwner.Memory.Span[..payloadLength], pool);
            }

            byte[] signature = DecodeBase64UrlToArray(signatureSegment.Span);
            ReadOnlyMemory<byte> signingInput = blobBytes[..secondDot];

            return new UnverifiedMetadataBlob(algorithm, x5c, signingInput, signature, payload);
        }
        catch(Exception exception) when(exception is JsonException or FormatException or OverflowException or InvalidOperationException)
        {
            DisposeCertificates(x5c);
            throw new Fido2FormatException("The Metadata BLOB bytes are not a well-formed compact JWS conforming to the Metadata BLOB syntax.", exception);
        }
        catch
        {
            DisposeCertificates(x5c);
            throw;
        }
    }


    /// <summary>
    /// Locates the two segment-separating <c>.</c> bytes of a compact-JWS buffer, rejecting a buffer
    /// with fewer than three segments (a bare JWT/detached JWS) or more than three (an unsupported
    /// serialization).
    /// </summary>
    private static (int FirstDot, int SecondDot) LocateSegments(ReadOnlySpan<byte> blobBytes)
    {
        int firstDot = blobBytes.IndexOf((byte)'.');
        if(firstDot < 0)
        {
            throw new Fido2FormatException("The Metadata BLOB is missing its header/payload segment separator.");
        }

        int secondDotOffset = blobBytes[(firstDot + 1)..].IndexOf((byte)'.');
        if(secondDotOffset < 0)
        {
            throw new Fido2FormatException("The Metadata BLOB is missing its payload/signature segment separator.");
        }

        int secondDot = firstDot + 1 + secondDotOffset;
        if(blobBytes[(secondDot + 1)..].IndexOf((byte)'.') >= 0)
        {
            throw new Fido2FormatException("The Metadata BLOB carries more than three compact-JWS segments.");
        }

        return (firstDot, secondDot);
    }


    /// <summary>
    /// Decodes and parses the JWT Header segment, returning its <c>alg</c> value and <c>x5c</c>
    /// certificate chain.
    /// </summary>
    private static string ReadHeader(ReadOnlySpan<byte> headerSegment, MemoryPool<byte> pool, out List<PkiCertificateMemory> x5c)
    {
        byte[] headerJson = DecodeBase64UrlToArray(headerSegment);

        return ReadHeaderObject(headerJson, pool, out x5c);
    }


    /// <summary>
    /// Reads the JWT Header JSON object, requiring <c>alg</c> and <c>x5c</c>, rejecting an <c>x5u</c>
    /// member outright (fetcher territory, out of scope), and skipping every other member.
    /// </summary>
    private static string ReadHeaderObject(ReadOnlySpan<byte> headerJson, MemoryPool<byte> pool, out List<PkiCertificateMemory> x5c)
    {
        Utf8JsonReader reader = new(headerJson, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The Metadata BLOB JWT Header top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? algorithm = null;
        List<PkiCertificateMemory>? certificates = null;
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"The Metadata BLOB JWT Header member '{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The Metadata BLOB JWT Header member '{memberName}' is truncated.");
                }

                _ = memberName switch
                {
                    _ when WellKnownJwkMemberNames.IsAlg(memberName) => AssignAlgorithm(ref reader, ref algorithm),
                    _ when WellKnownJwkMemberNames.IsX5c(memberName) => AssignCertificates(ref reader, pool, memberName, ref certificates),
                    _ when WellKnownJwkMemberNames.IsX5u(memberName) => throw new Fido2FormatException("The Metadata BLOB JWT Header carries an x5u member; this library implements the x5c trust branch only, per the FIDO Metadata Service v3.1 processing rules."),
                    _ => SkipValue(ref reader)
                };
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException("The Metadata BLOB JWT Header object is not terminated.");
            }

            if(algorithm is null)
            {
                throw new Fido2FormatException("The Metadata BLOB JWT Header member 'alg' is required.");
            }

            if(certificates is null)
            {
                throw new Fido2FormatException("The Metadata BLOB JWT Header member 'x5c' is required.");
            }

            x5c = certificates;

            return algorithm;
        }
        catch
        {
            DisposeCertificates(certificates);
            throw;
        }

        //Validates and assigns the alg member's string value to algorithm.
        static bool AssignAlgorithm(ref Utf8JsonReader reader, ref string? algorithm)
        {
            if(reader.TokenType != JsonTokenType.String)
            {
                throw new Fido2FormatException("The Metadata BLOB JWT Header member 'alg' MUST be a string.");
            }

            algorithm = reader.GetString()!;

            return true;
        }

        //Assigns the decoded x5c certificate chain to certificates.
        static bool AssignCertificates(ref Utf8JsonReader reader, MemoryPool<byte> pool, string memberName, ref List<PkiCertificateMemory>? certificates)
        {
            certificates = ReadBase64DerCertificateArray(ref reader, pool, memberName, requireNonEmpty: true);

            return true;
        }

        //Skips an unmodeled member's value.
        static bool SkipValue(ref Utf8JsonReader reader)
        {
            reader.Skip();

            return false;
        }
    }


    /// <summary>
    /// Reads a CBOR-free JSON array of standard (padded) base64 DER certificate strings, per RFC
    /// 7515 §4.1.6 — used for both the JWT Header's <c>x5c</c> and a metadata statement's
    /// <c>attestationRootCertificates</c>.
    /// </summary>
    /// <param name="reader">The reader, positioned at the array's value token.</param>
    /// <param name="pool">The memory pool each decoded certificate carrier rents from.</param>
    /// <param name="memberName">The member name, named in every rejection this method raises.</param>
    /// <param name="requireNonEmpty">
    /// Whether a present-but-empty array is rejected — <see langword="true"/> for <c>x5c</c>, the
    /// section 1 WebIDL "List MUST NOT be an empty list" rule (snapshot line 2340) applied as this
    /// library's own secure default even though <c>x5c</c> is an RFC 7515 header member, not an MDS
    /// v3.1 WebIDL dictionary member itself.
    /// </param>
    private static List<PkiCertificateMemory> ReadBase64DerCertificateArray(ref Utf8JsonReader reader, MemoryPool<byte> pool, string memberName, bool requireNonEmpty)
    {
        RejectNull(ref reader, memberName);

        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a JSON array.");
        }

        var certificates = new List<PkiCertificateMemory>();
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                if(reader.TokenType != JsonTokenType.String)
                {
                    throw new Fido2FormatException($"An element of member '{memberName}' MUST be a string.");
                }

                byte[] derBytes = Convert.FromBase64String(reader.GetString()!);
                IMemoryOwner<byte> owner = pool.Rent(derBytes.Length);
                derBytes.CopyTo(owner.Memory.Span);
                certificates.Add(new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate));
            }

            if(reader.TokenType != JsonTokenType.EndArray)
            {
                throw new Fido2FormatException($"The member '{memberName}' array is not terminated.");
            }

            if(requireNonEmpty && certificates.Count == 0)
            {
                throw new Fido2FormatException($"The member '{memberName}' MUST NOT be an empty list.");
            }

            return certificates;
        }
        catch
        {
            DisposeCertificates(certificates);
            throw;
        }
    }


    /// <summary>
    /// Decodes and parses the Metadata BLOB Payload JSON object.
    /// </summary>
    /// <param name="payloadJson">
    /// The decoded payload JSON bytes — the buffer every entry's
    /// <see cref="MetadataBlobPayloadEntry.RawMetadataStatement"/> copy is taken from.
    /// </param>
    /// <param name="pool">The memory pool a matched entry's attestation root certificates rent from.</param>
    private static UnverifiedMetadataBlobPayload ReadPayload(ReadOnlySpan<byte> payloadJson, MemoryPool<byte> pool)
    {
        Utf8JsonReader reader = new(payloadJson, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The Metadata BLOB Payload top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? legalHeader = null;
        long? no = null;
        DateOnly? nextUpdate = null;
        List<MetadataBlobPayloadEntry>? entries = null;
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"The Metadata BLOB Payload member '{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The Metadata BLOB Payload member '{memberName}' is truncated.");
                }

                _ = memberName switch
                {
                    LegalHeaderMember => AssignLegalHeader(ref reader, memberName, ref legalHeader),
                    NoMember => AssignNo(ref reader, memberName, ref no),
                    NextUpdateMember => AssignNextUpdate(ref reader, memberName, ref nextUpdate),
                    EntriesMember => AssignEntries(ref reader, payloadJson, pool, ref entries),
                    _ => SkipValue(ref reader)
                };
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload object is not terminated.");
            }

            if(no is null)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload member 'no' is required.");
            }

            if(nextUpdate is null)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload member 'nextUpdate' is required.");
            }

            if(entries is null)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload member 'entries' is required.");
            }

            return new UnverifiedMetadataBlobPayload(legalHeader, no.Value, nextUpdate.Value, entries);
        }
        catch
        {
            DisposeEntries(entries);
            throw;
        }

        //Assigns the decoded legalHeader string to legalHeader.
        static bool AssignLegalHeader(ref Utf8JsonReader reader, string memberName, ref string? legalHeader)
        {
            legalHeader = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Assigns the decoded no value to no.
        static bool AssignNo(ref Utf8JsonReader reader, string memberName, ref long? no)
        {
            no = ReadRequiredInt64(ref reader, memberName);

            return true;
        }

        //Assigns the decoded nextUpdate date to nextUpdate.
        static bool AssignNextUpdate(ref Utf8JsonReader reader, string memberName, ref DateOnly? nextUpdate)
        {
            nextUpdate = ReadRequiredDate(ref reader, memberName);

            return true;
        }

        //Assigns the decoded entries array to entries.
        static bool AssignEntries(ref Utf8JsonReader reader, ReadOnlySpan<byte> payloadJson, MemoryPool<byte> pool, ref List<MetadataBlobPayloadEntry>? entries)
        {
            entries = ReadEntriesArray(ref reader, payloadJson, pool);

            return true;
        }

        //Skips an unmodeled member's value.
        static bool SkipValue(ref Utf8JsonReader reader)
        {
            reader.Skip();

            return false;
        }
    }


    /// <summary>
    /// Reads the <c>entries</c> array, each element a Metadata BLOB Payload Entry object. Unlike
    /// <c>x5c</c> and <c>attestationCertificateKeyIdentifiers</c>, a present-but-empty array is
    /// accepted: the specification documents its own carve-out at snapshot line 2962 — "List of zero
    /// or more MetadataBLOBPayloadEntry objects" — so section 1's general WebIDL list-emptiness rule
    /// is expressly overridden for this member.
    /// </summary>
    private static List<MetadataBlobPayloadEntry> ReadEntriesArray(ref Utf8JsonReader reader, ReadOnlySpan<byte> payloadJson, MemoryPool<byte> pool)
    {
        RejectNull(ref reader, EntriesMember);

        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException("The Metadata BLOB Payload member 'entries' MUST be a JSON array.");
        }

        var entries = new List<MetadataBlobPayloadEntry>();
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                if(reader.TokenType != JsonTokenType.StartObject)
                {
                    throw new Fido2FormatException("A Metadata BLOB Payload entry MUST be a JSON object.");
                }

                entries.Add(ReadEntryObject(ref reader, payloadJson, pool));
            }

            if(reader.TokenType != JsonTokenType.EndArray)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload 'entries' array is not terminated.");
            }

            return entries;
        }
        catch
        {
            DisposeEntries(entries);
            throw;
        }
    }


    /// <summary>
    /// Reads a single Metadata BLOB Payload Entry object, requiring <c>metadataStatement</c> and
    /// <c>statusReports</c>.
    /// </summary>
    private static MetadataBlobPayloadEntry ReadEntryObject(ref Utf8JsonReader reader, ReadOnlySpan<byte> payloadJson, MemoryPool<byte> pool)
    {
        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? aaid = null;
        Guid? aaguid = null;
        List<string>? attestationCertificateKeyIdentifiers = null;
        List<MetadataStatusReport>? statusReports = null;
        DateOnly? timeOfLastStatusChange = null;
        List<PkiCertificateMemory>? attestationRootCertificates = null;
        ReadOnlyMemory<byte>? rawMetadataStatement = null;
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"The Metadata BLOB Payload entry member '{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The Metadata BLOB Payload entry member '{memberName}' is truncated.");
                }

                _ = memberName switch
                {
                    AaidMember => AssignAaid(ref reader, memberName, ref aaid),
                    AaguidMember => AssignAaguid(ref reader, memberName, ref aaguid),
                    AttestationCertificateKeyIdentifiersMember => AssignAttestationCertificateKeyIdentifiers(ref reader, memberName, ref attestationCertificateKeyIdentifiers),
                    MetadataStatementMember => AssignMetadataStatement(ref reader, payloadJson, pool, ref attestationRootCertificates, ref rawMetadataStatement),
                    StatusReportsMember => AssignStatusReports(ref reader, ref statusReports),
                    TimeOfLastStatusChangeMember => AssignTimeOfLastStatusChange(ref reader, memberName, ref timeOfLastStatusChange),
                    _ => SkipValue(ref reader)
                };
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload entry object is not terminated.");
            }

            if(rawMetadataStatement is null)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload entry member 'metadataStatement' is required.");
            }

            if(statusReports is null)
            {
                throw new Fido2FormatException("The Metadata BLOB Payload entry member 'statusReports' is required.");
            }

            if(aaid is null && aaguid is null && attestationCertificateKeyIdentifiers is null)
            {
                throw new Fido2FormatException(
                    "The Metadata BLOB Payload entry MUST set at least one of 'aaid', 'aaguid', or 'attestationCertificateKeyIdentifiers'.");
            }

            return new MetadataBlobPayloadEntry(
                aaguid, aaid, attestationCertificateKeyIdentifiers, statusReports, timeOfLastStatusChange,
                attestationRootCertificates, rawMetadataStatement.Value);
        }
        catch
        {
            DisposeCertificates(attestationRootCertificates);
            throw;
        }

        //Assigns the decoded aaid string to aaid.
        static bool AssignAaid(ref Utf8JsonReader reader, string memberName, ref string? aaid)
        {
            aaid = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Validates and assigns the decoded aaguid GUID to aaguid.
        static bool AssignAaguid(ref Utf8JsonReader reader, string memberName, ref Guid? aaguid)
        {
            string aaguidText = ReadRequiredString(ref reader, memberName);
            if(!Guid.TryParseExact(aaguidText, CanonicalGuidFormat, out Guid parsedAaguid))
            {
                throw new Fido2FormatException($"The Metadata BLOB Payload entry member 'aaguid' value '{aaguidText}' is not a canonical GUID string.");
            }

            aaguid = parsedAaguid;

            return true;
        }

        //Assigns the decoded attestationCertificateKeyIdentifiers array to
        //attestationCertificateKeyIdentifiers.
        static bool AssignAttestationCertificateKeyIdentifiers(ref Utf8JsonReader reader, string memberName, ref List<string>? attestationCertificateKeyIdentifiers)
        {
            attestationCertificateKeyIdentifiers = ReadAttestationCertificateKeyIdentifiersArray(ref reader, memberName);

            return true;
        }

        //Assigns the decoded metadataStatement's attestation root certificates and raw JSON
        //bytes to attestationRootCertificates and rawMetadataStatement.
        static bool AssignMetadataStatement(
            ref Utf8JsonReader reader, ReadOnlySpan<byte> payloadJson, MemoryPool<byte> pool,
            ref List<PkiCertificateMemory>? attestationRootCertificates, ref ReadOnlyMemory<byte>? rawMetadataStatement)
        {
            (attestationRootCertificates, rawMetadataStatement) = ReadMetadataStatement(ref reader, payloadJson, pool);

            return true;
        }

        //Assigns the decoded statusReports array to statusReports.
        static bool AssignStatusReports(ref Utf8JsonReader reader, ref List<MetadataStatusReport>? statusReports)
        {
            statusReports = ReadStatusReportsArray(ref reader);

            return true;
        }

        //Assigns the decoded timeOfLastStatusChange date to timeOfLastStatusChange, dispatched
        //from the Metadata BLOB Payload entry's member-name switch.
        static bool AssignTimeOfLastStatusChange(ref Utf8JsonReader reader, string memberName, ref DateOnly? timeOfLastStatusChange)
        {
            timeOfLastStatusChange = ReadRequiredDate(ref reader, memberName);

            return true;
        }

        //Skips an unmodeled member's value.
        static bool SkipValue(ref Utf8JsonReader reader)
        {
            reader.Skip();

            return false;
        }
    }


    /// <summary>
    /// Reads a <c>metadataStatement</c> object, lifting its <c>attestationRootCertificates</c> member
    /// (if present) into typed certificate carriers and copying the object's own raw JSON bytes out
    /// of <paramref name="payloadJson"/> into an independent array. A present-but-empty
    /// <c>attestationRootCertificates</c> array is accepted (unlike <c>x5c</c> and
    /// <c>attestationCertificateKeyIdentifiers</c>): the term does not appear anywhere in the FIDO
    /// Metadata Service v3.1 specification text at all — it is a <c>MetadataStatement</c> ([FIDOMetadataStatement],
    /// a separate, unmodeled specification) member this reader lifts out purely as a convenience, so
    /// MDS v3.1 section 1's "unless otherwise specified… in this document" WebIDL list-emptiness rule
    /// does not govern it, and <see cref="MetadataBlobPayloadQueries.GetAttestationTrustAnchors"/>
    /// already treats "absent" and "present but empty" identically (zero trust anchors either way).
    /// </summary>
    private static (List<PkiCertificateMemory>? AttestationRootCertificates, byte[] Raw) ReadMetadataStatement(
        ref Utf8JsonReader reader, ReadOnlySpan<byte> payloadJson, MemoryPool<byte> pool)
    {
        RejectNull(ref reader, MetadataStatementMember);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The Metadata BLOB Payload entry member 'metadataStatement' MUST be a JSON object.");
        }

        long start = reader.TokenStartIndex;
        List<PkiCertificateMemory>? attestationRootCertificates = null;
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The metadataStatement member '{memberName}' is truncated.");
                }

                if(string.Equals(memberName, AttestationRootCertificatesMember, StringComparison.Ordinal))
                {
                    if(attestationRootCertificates is not null)
                    {
                        throw new Fido2FormatException("The metadataStatement member 'attestationRootCertificates' is repeated.");
                    }

                    attestationRootCertificates = ReadBase64DerCertificateArray(ref reader, pool, AttestationRootCertificatesMember, requireNonEmpty: false);
                }
                else
                {
                    reader.Skip();
                }
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException("The metadataStatement object is not terminated.");
            }

            long end = reader.BytesConsumed;
            byte[] raw = payloadJson.Slice(checked((int)start), checked((int)(end - start))).ToArray();

            return (attestationRootCertificates, raw);
        }
        catch
        {
            DisposeCertificates(attestationRootCertificates);
            throw;
        }
    }


    /// <summary>
    /// Reads the <c>statusReports</c> array, each element a <see cref="MetadataStatusReport"/>.
    /// </summary>
    private static List<MetadataStatusReport> ReadStatusReportsArray(ref Utf8JsonReader reader)
    {
        RejectNull(ref reader, StatusReportsMember);

        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException("The Metadata BLOB Payload entry member 'statusReports' MUST be a JSON array.");
        }

        var reports = new List<MetadataStatusReport>();
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                throw new Fido2FormatException("A statusReports array element MUST be a JSON object.");
            }

            reports.Add(ReadStatusReportObject(ref reader));
        }

        if(reader.TokenType != JsonTokenType.EndArray)
        {
            throw new Fido2FormatException("The 'statusReports' array is not terminated.");
        }

        return reports;
    }


    /// <summary>
    /// Reads a single <c>StatusReport</c> object, requiring <c>status</c>.
    /// </summary>
    private static MetadataStatusReport ReadStatusReportObject(ref Utf8JsonReader reader)
    {
        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? status = null;
        DateOnly? effectiveDate = null;
        string? certificate = null;
        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The status report member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The status report member '{memberName}' is truncated.");
            }

            _ = memberName switch
            {
                StatusMember => AssignStatus(ref reader, memberName, ref status),
                EffectiveDateMember => AssignEffectiveDate(ref reader, memberName, ref effectiveDate),
                CertificateMember => AssignCertificate(ref reader, memberName, ref certificate),
                _ => SkipValue(ref reader)
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("A status report object is not terminated.");
        }

        if(status is null)
        {
            throw new Fido2FormatException("The status report member 'status' is required.");
        }

        return new MetadataStatusReport(status, effectiveDate, certificate);

        //Assigns the decoded status string to status.
        static bool AssignStatus(ref Utf8JsonReader reader, string memberName, ref string? status)
        {
            status = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Assigns the decoded effectiveDate date to effectiveDate.
        static bool AssignEffectiveDate(ref Utf8JsonReader reader, string memberName, ref DateOnly? effectiveDate)
        {
            effectiveDate = ReadRequiredDate(ref reader, memberName);

            return true;
        }

        //Assigns the decoded certificate string to certificate.
        static bool AssignCertificate(ref Utf8JsonReader reader, string memberName, ref string? certificate)
        {
            certificate = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Skips an unmodeled member's value.
        static bool SkipValue(ref Utf8JsonReader reader)
        {
            reader.Skip();

            return false;
        }
    }


    /// <summary>
    /// Reads a JSON array of strings — the <c>attestationCertificateKeyIdentifiers</c> shape.
    /// </summary>
    private static List<string> ReadStringArray(ref Utf8JsonReader reader, string memberName)
    {
        RejectNull(ref reader, memberName);

        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a JSON array.");
        }

        var values = new List<string>();
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.String)
            {
                throw new Fido2FormatException($"An element of member '{memberName}' MUST be a string.");
            }

            values.Add(reader.GetString()!);
        }

        if(reader.TokenType != JsonTokenType.EndArray)
        {
            throw new Fido2FormatException($"The member '{memberName}' array is not terminated.");
        }

        return values;
    }


    /// <summary>
    /// Reads the <c>attestationCertificateKeyIdentifiers</c> array, additionally enforcing the
    /// producer-format rules FIDO Metadata Service v3.1 section 3.1.1 states for each hex string
    /// element (snapshot lines 2414/2416) and the section 1 WebIDL "List MUST NOT be an empty list"
    /// rule (snapshot line 2340) for the array itself.
    /// </summary>
    private static List<string> ReadAttestationCertificateKeyIdentifiersArray(ref Utf8JsonReader reader, string memberName)
    {
        List<string> values = ReadStringArray(ref reader, memberName);
        if(values.Count == 0)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST NOT be an empty list.");
        }

        foreach(string identifier in values)
        {
            if(identifier.Length == 0)
            {
                throw new Fido2FormatException($"An element of member '{memberName}' MUST NOT be empty.");
            }

            foreach(char character in identifier)
            {
                if(character is (>= '0' and <= '9') or (>= 'a' and <= 'f'))
                {
                    continue;
                }

                if(character is >= 'A' and <= 'F')
                {
                    throw new Fido2FormatException($"The member '{memberName}' element '{identifier}' MUST use lower case hex letters only.");
                }

                throw new Fido2FormatException($"The member '{memberName}' element '{identifier}' MUST NOT contain any non-hex characters.");
            }
        }

        return values;
    }


    /// <summary>
    /// Reads the reader's current value as a non-empty string, naming <paramref name="memberName"/>
    /// in the rejection when the value is not string-shaped.
    /// </summary>
    private static string ReadRequiredString(ref Utf8JsonReader reader, string memberName)
    {
        RejectNull(ref reader, memberName);

        if(reader.TokenType != JsonTokenType.String)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a string.");
        }

        string value = reader.GetString()!;
        if(value.Length == 0)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST NOT be empty.");
        }

        return value;
    }


    /// <summary>
    /// Reads the reader's current value as a 64-bit integer, naming <paramref name="memberName"/> in
    /// the rejection when the value is not number-shaped.
    /// </summary>
    private static long ReadRequiredInt64(ref Utf8JsonReader reader, string memberName)
    {
        RejectNull(ref reader, memberName);

        if(reader.TokenType != JsonTokenType.Number)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a number.");
        }

        return reader.GetInt64();
    }


    /// <summary>
    /// Rejects an explicit JSON <c>null</c> as <paramref name="memberName"/>'s value — the FIDO
    /// Metadata Service v3.1 section 1 WebIDL rule "dictionary members MUST NOT have a value of
    /// null" (snapshot line 2338), enforced as a dedicated, precisely-messaged guard rather than
    /// left to an incidental token-type mismatch in each caller's own shape check. An absent member
    /// (the key never appears at all) is unaffected — this rejects only an explicit <c>null</c>
    /// token supplied as the member's value; absent and null are different, and only the latter is
    /// malformed.
    /// </summary>
    private static void RejectNull(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType == JsonTokenType.Null)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST NOT have a value of null.");
        }
    }


    /// <summary>
    /// Reads the reader's current value as an ISO-8601 (<c>yyyy-MM-dd</c>) date string, naming
    /// <paramref name="memberName"/> in the rejection when the value is not a string or not a valid
    /// date in that exact format.
    /// </summary>
    private static DateOnly ReadRequiredDate(ref Utf8JsonReader reader, string memberName)
    {
        string text = ReadRequiredString(ref reader, memberName);
        if(!DateOnly.TryParseExact(text, DateFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date))
        {
            throw new Fido2FormatException($"The member '{memberName}' value '{text}' is not an ISO-8601 (yyyy-MM-dd) date.");
        }

        return date;
    }


    /// <summary>
    /// Decodes a base64url (no padding) segment into a plain managed array — used for the JWT
    /// Header and JWS Signature segments, whose decoded bytes are not retained beyond this call
    /// (the header) or need no pooled tracking (the signature, mirroring
    /// <c>PackedAttestationStatement.Signature</c>'s plain-array shape).
    /// </summary>
    private static byte[] DecodeBase64UrlToArray(ReadOnlySpan<byte> segment)
    {
        byte[] buffer = new byte[Base64Url.GetMaxDecodedLength(segment.Length)];
        if(!Base64Url.TryDecodeFromUtf8(segment, buffer, out int bytesWritten))
        {
            throw new Fido2FormatException("A Metadata BLOB segment is not valid base64url.");
        }

        return bytesWritten == buffer.Length ? buffer : buffer[..bytesWritten];
    }


    /// <summary>
    /// Decodes a base64url (no padding) segment into a pooled buffer — used for the JWS Payload
    /// segment, whose decoded bytes are only needed transiently while <see cref="ReadPayload"/>
    /// parses them: every entry's <see cref="MetadataBlobPayloadEntry.RawMetadataStatement"/> is an
    /// independent copy, not an alias into this buffer, so the caller disposes this buffer as soon
    /// as parsing completes.
    /// </summary>
    private static IMemoryOwner<byte> DecodeBase64UrlToPooledBuffer(ReadOnlySpan<byte> segment, MemoryPool<byte> pool, out int length)
    {
        int maxLength = Base64Url.GetMaxDecodedLength(segment.Length);
        IMemoryOwner<byte> owner = pool.Rent(maxLength);
        try
        {
            if(!Base64Url.TryDecodeFromUtf8(segment, owner.Memory.Span, out int bytesWritten))
            {
                throw new Fido2FormatException("A Metadata BLOB segment is not valid base64url.");
            }

            length = bytesWritten;

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Disposes every certificate carrier in <paramref name="certificates"/>, if any. Called on
    /// every failure path so a rejected or malformed BLOB never leaks pooled memory.
    /// </summary>
    private static void DisposeCertificates(List<PkiCertificateMemory>? certificates)
    {
        if(certificates is not null)
        {
            foreach(PkiCertificateMemory certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }


    /// <summary>
    /// Disposes every entry in <paramref name="entries"/>, if any — releasing each entry's own
    /// attestation root certificates. Called on every failure path so a rejected or malformed BLOB
    /// never leaks pooled memory.
    /// </summary>
    private static void DisposeEntries(List<MetadataBlobPayloadEntry>? entries)
    {
        if(entries is not null)
        {
            foreach(MetadataBlobPayloadEntry entry in entries)
            {
                entry.Dispose();
            }
        }
    }
}
