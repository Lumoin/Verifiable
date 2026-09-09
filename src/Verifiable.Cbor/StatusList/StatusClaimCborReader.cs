using Lumoin.Veritas.Cbor;
using Verifiable.Core.StatusList;

namespace Verifiable.Cbor.StatusList;

/// <summary>
/// Reader for the Status CBOR structure a COSE-based Referenced Token carries — the one decoder
/// every COSE format's status claim flows through.
/// </summary>
/// <remarks>
/// <para>
/// Per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
/// Token Status List, Section 6.3</see>: "The Status CBOR structure is a Map that MUST include at
/// least one data item that refers to a status mechanism. Each data item in the Status CBOR
/// structure comprises a key-value pair, where the key MUST be a CBOR text string (major type 3)
/// specifying the identifier of the status mechanism and the corresponding value defines its
/// contents." and "status_list (status list): REQUIRED when the status mechanism defined in this
/// specification is used. It has the same definition as the status_list claim in Section 6.2 but
/// MUST be encoded as a StatusListInfo CBOR structure".
/// </para>
/// <para>
/// The same section states the Referenced Token "MAY be encoded as a "CBOR Web Token (CWT)" object
/// according to [RFC8392], as an SD-CWTs [I-D.ietf-spice-sd-cwt] or as an ISO mdoc", so one reader
/// serves the mdoc Mobile Security Object's <c>status</c> member and the SD-CWT's <c>status</c> CWT
/// claim alike; both yield a <see cref="StatusClaim"/>.
/// </para>
/// </remarks>
public static class StatusClaimCborReader
{
    /// <summary>
    /// Reads the Status CBOR structure the supplied reader is positioned on: a map of text-string
    /// mechanism keys to mechanism-specific values. <c>status_list</c> decodes through
    /// <see cref="ReadStatusListReferenceStrict"/>; every other mechanism key is recorded by name
    /// into <see cref="StatusClaim.Mechanisms"/> and its value skipped, the forward-compatibility
    /// posture an unrecognised key gets everywhere else in this leaf.
    /// </summary>
    /// <param name="reader">The reader, positioned at the start of the Status map.</param>
    /// <returns>The decoded status claim.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map carries no entry (Section 6.3's "at least one data item"), when a key is
    /// not a text string (Section 6.3's "the key MUST be a CBOR text string (major type 3)"), when a
    /// mechanism key repeats, or when a <c>status_list</c> value leaves Section 6.3's value domain.
    /// This is the one refusal family the reader answers a malformed Status structure with, so a
    /// caller classifying a wire-shape rejection names a single type.
    /// </exception>
    public static StatusClaim Read(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        int? entryCount = reader.ReadStartMap();

        StatusListReference? statusListReference = null;
        HashSet<string> mechanisms = new(StringComparer.Ordinal);

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            //Section 6.3: "Each data item in the Status CBOR structure comprises a key-value pair,
            //where the key MUST be a CBOR text string (major type 3) specifying the identifier of
            //the status mechanism and the corresponding value defines its contents." A key of any
            //other major type is refused in this reader's own family rather than surfacing as the
            //CborReader's argument-state exception, which a caller outside this leaf cannot name.
            CborReaderState keyState = reader.PeekState();
            if(keyState != CborReaderState.TextString)
            {
                throw new CborContentException(
                    $"The status claim's mechanism key must be encoded as CBOR {CborReaderState.TextString} " +
                    $"per Token Status List Section 6.3; got {keyState}.");
            }

            string mechanism = reader.ReadTextString();
            entriesRead++;

            //A repeated mechanism identifier lets one producer show one reader one mechanism and
            //another reader a different one — the same one-producer-two-readings hazard the JOSE
            //reader refuses a duplicate top-level member name for. The map's later entry would
            //otherwise silently overwrite the earlier one.
            if(!mechanisms.Add(mechanism))
            {
                throw new CborContentException(
                    $"The status claim repeats the status-mechanism key '{mechanism}'; " +
                    "Token Status List Section 6.3's data items each name one status mechanism.");
            }

            //StatusMechanismNames.StatusList aliases the single status_list literal in the JOSE
            //tier, which is a static readonly string rather than a compile-time constant, so the
            //mechanism is matched by an ordinal comparison instead of a constant switch arm.
            _ = string.Equals(mechanism, StatusMechanismNames.StatusList, StringComparison.Ordinal) switch
            {
                true => AssignStatusListReference(reader, ref statusListReference),
                false => SkipValue(reader)
            };
        }

        reader.ReadEndMap();

        if(mechanisms.Count == 0)
        {
            throw new CborContentException(
                "The status claim is missing at least one status-mechanism entry per Token Status List Section 6.3.");
        }

        return new StatusClaim(statusListReference, mechanisms);

        //Assigns the decoded status_list reference.
        static bool AssignStatusListReference(CborReader reader, ref StatusListReference? statusListReference)
        {
            statusListReference = ReadStatusListReferenceStrict(reader);

            return true;
        }

        //Unknown mechanism keys: forward-compat skip, applied inside the Status map.
        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return true;
        }
    }


    /// <summary>
    /// Reads a <c>status_list</c> value into a
    /// <see cref="StatusListReference"/>, owning the whole Section 6.3 value
    /// domain — major types, <c>idx</c>'s upper bound, and <c>uri</c>'s
    /// RFC 3986 conformance — before <see cref="StatusListReferenceCborConverter"/>
    /// ever runs: the converter's own <c>ReadInt32</c> overflows on an
    /// <c>idx</c> above <see cref="int.MaxValue"/> and
    /// <see cref="StatusListReference"/>'s constructor throws an API-misuse
    /// exception type for a negative, empty, or non-conforming value, none of
    /// which belong on this wire-read path. Validating first means every
    /// malformed shape surfaces as this method's own <see cref="CborContentException"/>,
    /// the same read-failure family every other malformed field in this
    /// leaf uses.
    /// </summary>
    /// <param name="reader">The reader, positioned at the <c>status_list</c> value.</param>
    /// <returns>The decoded reference.</returns>
    /// <exception cref="CborContentException">Thrown when the value leaves Section 6.3's value domain.</exception>
    private static StatusListReference ReadStatusListReferenceStrict(CborReader reader)
    {
        ReadOnlyMemory<byte> encoded = reader.ReadEncodedValue();

        var validatingReader = new CborReader(encoded, CborOptions.Lax);
        ValidateStatusListReferenceValueDomain(validatingReader);

        var decodingReader = new CborReader(encoded, CborOptions.Lax);
        var converter = new StatusListReferenceCborConverter();

        return converter.Read(decodingReader);
    }


    /// <summary>
    /// Walks a <c>status_list</c> map confirming <c>idx</c> is an unsigned
    /// integer no greater than <see cref="int.MaxValue"/> and <c>uri</c> is a
    /// text string conforming to RFC 3986, per Section 6.3's "idx: REQUIRED.
    /// Unsigned integer (major type 0). ... uri: REQUIRED. Text string
    /// (major type 3). ... The value of uri MUST be a URI conforming to
    /// [RFC3986]." Throws on the first mismatch. Consumes the supplied
    /// reader fully; callers pass a reader over a read-only view of the
    /// encoded <c>status_list</c> value within the enclosing buffer (no copy, no
    /// ownership transfer), so the caller's own reader position is
    /// unaffected.
    /// </summary>
    /// <param name="reader">A reader over the encoded <c>status_list</c> value alone.</param>
    /// <exception cref="CborContentException">Thrown on the first value-domain mismatch.</exception>
    private static void ValidateStatusListReferenceValueDomain(CborReader reader)
    {
        int? entryCount = reader.ReadStartMap();

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            string key = reader.ReadTextString();
            entriesRead++;

            _ = key switch
            {
                StatusListCborConstants.Index => RequireIndexInRange(reader),
                StatusListCborConstants.Uri => RequireConformingUri(reader),
                _ => SkipValue(reader)
            };
        }

        reader.ReadEndMap();

        //Confirms idx is an unsigned integer within Int32's range before the converter's ReadInt32 runs.
        static bool RequireIndexInRange(CborReader reader)
        {
            CborReaderState actual = reader.PeekState();
            if(actual != CborReaderState.UnsignedInteger)
            {
                throw new CborContentException(
                    $"status_list '{StatusListCborConstants.Index}' must be encoded as CBOR " +
                    $"{CborReaderState.UnsignedInteger} per Token Status List Section 6.3; got {actual}.");
            }

            ulong value = reader.ReadUInt64();
            if(value > int.MaxValue)
            {
                throw new CborContentException(
                    $"status_list '{StatusListCborConstants.Index}' of {value} exceeds Int32.MaxValue; " +
                    "Token Status List Section 6.3's idx must be a non-negative Integer this library can represent.");
            }

            return true;
        }

        //Confirms uri is a text string conforming to RFC 3986 before the converter constructs the reference.
        static bool RequireConformingUri(CborReader reader)
        {
            CborReaderState actual = reader.PeekState();
            if(actual != CborReaderState.TextString)
            {
                throw new CborContentException(
                    $"status_list '{StatusListCborConstants.Uri}' must be encoded as CBOR " +
                    $"{CborReaderState.TextString} per Token Status List Section 6.3; got {actual}.");
            }

            string value = reader.ReadTextString();
            if(!StatusListReference.IsConformingUri(value))
            {
                throw new CborContentException(
                    $"status_list '{StatusListCborConstants.Uri}' must be a URI conforming to RFC 3986 per " +
                    $"Token Status List Section 6.3; got '{value}'.");
            }

            return true;
        }

        //Members beyond idx and uri: forward-compat skip, per Section 6.2's "It MUST at least contain".
        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return true;
        }
    }
}
