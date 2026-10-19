using Lumoin.Veritas.Cbor;
using System.Globalization;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// CBOR reader for COSE_Key (RFC 9052 §7) producing the format-agnostic
/// <see cref="CoseKey"/> view used by the MSO <c>DeviceKeyInfo</c>
/// substructure.
/// </summary>
/// <remarks>
/// <para>
/// COSE_Key is an integer-keyed CBOR map per RFC 9052 §7.1. The reader
/// recognises the common parameters
/// (<see cref="CoseKeyParameters.Kty"/>, <see cref="CoseKeyParameters.Alg"/>,
/// <see cref="CoseKeyParameters.Crv"/>, <see cref="CoseKeyParameters.X"/>,
/// <see cref="CoseKeyParameters.Y"/>) and copies the byte-string fields
/// into managed arrays at parse time so the caller doesn't need to keep the
/// source buffer alive. Unknown integer keys are skipped without error per
/// the COSE forward-compatibility convention.
/// </para>
/// </remarks>
public static class MdocCborCoseKeyReader
{
    /// <summary>
    /// Reads a COSE_Key from the supplied CBOR bytes.
    /// </summary>
    /// <param name="encodedCoseKey">The CBOR-encoded COSE_Key bytes.</param>
    /// <returns>The parsed <see cref="CoseKey"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the bytes are not a valid CBOR map, when the
    /// mandatory <see cref="CoseKeyParameters.Kty"/> parameter is missing, or when a label appears
    /// twice in the map (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>:
    /// "When processing messages, if a label appears multiple times, the message MUST be rejected as malformed.").
    /// </exception>
    public static CoseKey Read(ReadOnlySpan<byte> encodedCoseKey)
    {
        var reader = new CborReader(encodedCoseKey.ToArray(), CborOptions.Lax);

        return ReadCoseKey(reader, isRepeatRefused: true, out _);
    }


    /// <summary>
    /// Reads a COSE_Key from the supplied CBOR bytes, additionally reporting the top-level integer
    /// labels encountered while parsing it.
    /// </summary>
    /// <param name="encodedCoseKey">The CBOR-encoded COSE_Key bytes.</param>
    /// <param name="labels">
    /// Receives the top-level integer labels within the 32-bit signed range encountered while parsing, in wire
    /// order, including duplicates if the wire bytes carried any: this overload passes every such label to the
    /// caller, which performs the duplicate check (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052
    /// Section 9</see>: "Applications can enforce the parse-and-process requirement by using parsers that
    /// will fail the parse step or by using parsers that will pass all keys to the application, and the
    /// application can perform the check for duplicate keys."). A label the list cannot carry, a text string or an
    /// integer outside that range, is judged for a repeat by the reader itself and passed over.
    /// </param>
    /// <returns>The parsed <see cref="CoseKey"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the bytes are not a valid CBOR map, when the mandatory <see cref="CoseKeyParameters.Kty"/>
    /// parameter is missing, when a map key is neither an integer nor a text string, or when a label the list
    /// cannot carry appears twice.
    /// </exception>
    public static CoseKey Read(ReadOnlySpan<byte> encodedCoseKey, out IReadOnlyList<int> labels)
    {
        var reader = new CborReader(encodedCoseKey.ToArray(), CborOptions.Lax);

        return ReadFromReader(reader, out labels);
    }


    /// <summary>
    /// Reads a COSE_Key from an existing <see cref="CborReader"/> positioned
    /// at the start of the map. Useful when composing parses (e.g.
    /// <see cref="MdocCborMsoReader"/> reading the <c>deviceKey</c> field
    /// from inside the MSO <c>DeviceKeyInfo</c> map).
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the start of the COSE_Key map.</param>
    /// <returns>The parsed <see cref="CoseKey"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when a label appears twice in the map
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When
    /// processing messages, if a label appears multiple times, the message MUST be rejected as malformed."),
    /// or when the map is otherwise not a valid COSE_Key.
    /// </exception>
    public static CoseKey ReadFromReader(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        return ReadCoseKey(reader, isRepeatRefused: true, out _);
    }


    /// <summary>
    /// Reads a COSE_Key from an existing <see cref="CborReader"/> positioned at the start of the map,
    /// additionally reporting the top-level integer labels encountered while parsing it.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the start of the COSE_Key map.</param>
    /// <param name="labels">
    /// Receives the top-level integer labels within the 32-bit signed range encountered while parsing, in wire
    /// order, including duplicates if the wire bytes carried any: this overload passes every such label to the
    /// caller, which performs the duplicate check (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052
    /// Section 9</see>: "Applications can enforce the parse-and-process requirement by using parsers that
    /// will fail the parse step or by using parsers that will pass all keys to the application, and the
    /// application can perform the check for duplicate keys."). A label the list cannot carry, a text string or an
    /// integer outside that range, is judged for a repeat by the reader itself and passed over.
    /// </param>
    /// <returns>The parsed <see cref="CoseKey"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the map is not a valid COSE_Key, when a map key is neither an integer nor a text string, or when
    /// a label the list cannot carry appears twice.
    /// </exception>
    public static CoseKey ReadFromReader(CborReader reader, out IReadOnlyList<int> labels)
    {
        ArgumentNullException.ThrowIfNull(reader);

        return ReadCoseKey(reader, isRepeatRefused: false, out labels);
    }


    /// <summary>
    /// Reads a COSE_Key map whole. Every label is read as RFC 9052 Section 1.5 defines it, any CBOR integer read whole
    /// or a text string, so a label is never read as the label its low 32 bits spell; a well-formed label the
    /// <see cref="CoseKey"/> view does not carry is passed over with its value. A label that appears twice is refused
    /// here when <paramref name="isRepeatRefused"/> is set; otherwise every integer label within the 32-bit signed
    /// range is passed to the caller in <paramref name="labels"/> for the caller's own check, and the labels the list
    /// cannot carry are judged here.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When processing
    /// messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr".
    /// </remarks>
    /// <param name="reader">The CBOR reader positioned at the start of the COSE_Key map.</param>
    /// <param name="isRepeatRefused">Whether a repeated label within the 32-bit signed range is refused here.</param>
    /// <param name="labels">Receives the integer labels within the 32-bit signed range, in wire order.</param>
    /// <returns>The parsed <see cref="CoseKey"/>.</returns>
    /// <exception cref="CborContentException">
    /// The map repeats a label this call judges, carries a map key that is neither an integer nor a text string, lacks
    /// <see cref="CoseKeyParameters.Kty"/>, or is otherwise not a valid COSE_Key.
    /// </exception>
    private static CoseKey ReadCoseKey(CborReader reader, bool isRepeatRefused, out IReadOnlyList<int> labels)
    {
        int? entryCount = reader.ReadStartMap();

        int? kty = null;
        int? alg = null;
        int? curve = null;
        ReadOnlyMemory<byte>? x = null;
        ReadOnlyMemory<byte>? y = null;
        bool? encodedYCompressionSign = null;
        var encounteredLabels = new List<int>();
        HashSet<(Int128 Number, string? Text)> judgedLabels = [];

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            (Int128 Number, string? Text) label = ReadLabel(reader);
            entriesRead++;

            bool isListLabel = label.Text is null && label.Number >= int.MinValue && label.Number <= int.MaxValue;
            if(isListLabel && !isRepeatRefused)
            {
                encounteredLabels.Add((int)label.Number);
            }
            else if(!judgedLabels.Add(label))
            {
                throw new CborContentException(
                    $"COSE_Key label {label.Text ?? label.Number.ToString(CultureInfo.InvariantCulture)} appears more than once in one map; the COSE_Key is malformed (RFC 9052 Section 3).");
            }

            int? viewLabel = isListLabel ? (int)label.Number : null;
            _ = viewLabel switch
            {
                CoseKeyParameters.Kty => AssignKty(reader, ref kty),
                CoseKeyParameters.Alg => AssignAlg(reader, ref alg),
                CoseKeyParameters.Crv => AssignCrv(reader, ref curve),
                CoseKeyParameters.X => AssignX(reader, ref x),
                CoseKeyParameters.Y => AssignY(reader, ref y, ref encodedYCompressionSign),
                _ => SkipValue(reader)
            };
        }

        reader.ReadEndMap();
        labels = encounteredLabels;

        if(kty is null)
        {
            throw new CborContentException(
                "COSE_Key is missing the mandatory kty (1) parameter per RFC 9052 §7.1.");
        }

        return new CoseKey(
            kty: kty.Value,
            alg: alg,
            curve: curve,
            x: x,
            y: y,
            encodedYCompressionSign: encodedYCompressionSign);

        //Assigns the decoded key type identifier to kty.
        static bool AssignKty(CborReader reader, ref int? kty)
        {
            kty = ReadIdentifier(reader);

            return true;
        }

        //Assigns the decoded algorithm identifier to alg.
        static bool AssignAlg(CborReader reader, ref int? alg)
        {
            alg = ReadIdentifier(reader);

            return true;
        }

        //Assigns the decoded curve identifier to curve.
        static bool AssignCrv(CborReader reader, ref int? curve)
        {
            curve = ReadIdentifier(reader);

            return true;
        }

        //Assigns the decoded x-coordinate to x.
        static bool AssignX(CborReader reader, ref ReadOnlyMemory<byte>? x)
        {
            x = reader.ReadByteString();

            return true;
        }

        //Assigns the decoded y-coordinate or compressed-sign flag to y or encodedYCompressionSign.
        //Y is either a byte string (uncompressed coordinate) or a bool (compressed sign); the next
        //reader state selects which.
        static bool AssignY(CborReader reader, ref ReadOnlyMemory<byte>? y, ref bool? encodedYCompressionSign)
        {
            if(reader.PeekState() == CborReaderState.Boolean)
            {
                encodedYCompressionSign = reader.ReadBoolean();
            }
            else
            {
                y = reader.ReadByteString();
            }

            return true;
        }

        //Skips an unrecognised label's value per the COSE forward-compatibility convention.
        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return true;
        }
    }


    /// <summary>
    /// Reads a COSE_Key integer identifier (the <c>kty</c>, <c>alg</c> or <c>crv</c> value) whole and refuses one
    /// outside the 32-bit signed range the key view carries, so a value is never read as the identifier its low 32 bits
    /// spell.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-7.1">RFC 9052 Section 7.1</see>: "The key type MUST be
    /// included as part of the trust-decision process."
    /// </remarks>
    /// <param name="reader">The reader, positioned at the identifier.</param>
    /// <returns>The identifier.</returns>
    /// <exception cref="CborContentException">The identifier lies outside the 32-bit signed range.</exception>
    private static int ReadIdentifier(CborReader reader)
    {
        long identifier = reader.ReadInt64();
        if(identifier is < int.MinValue or > int.MaxValue)
        {
            throw new CborContentException(
                $"A COSE_Key identifier {identifier.ToString(CultureInfo.InvariantCulture)} lies outside the range this reader carries; the key is refused (RFC 9052 Section 7.1).");
        }

        return (int)identifier;
    }


    /// <summary>
    /// Reads one COSE_Key label as RFC 9052 Section 1.5 defines it: any CBOR integer, negative or unsigned, read whole
    /// and never cast down, or a text string. Two labels are the same when their decoded values are equal; an integer
    /// and a text string are never the same. This is the one label read of this file.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr"
    /// and "In a CBOR map defined by this specification, the presence a label that is neither a text string nor an
    /// integer is an error." This reader fails processing.
    /// </remarks>
    /// <param name="reader">The reader, positioned at a COSE_Key label.</param>
    /// <returns>The decoded label: its integer value, or its text when it is a text string.</returns>
    /// <exception cref="CborContentException">The map key is neither an integer nor a text string.</exception>
    private static (Int128 Number, string? Text) ReadLabel(CborReader reader)
    {
        return reader.PeekState() switch
        {
            CborReaderState.UnsignedInteger => ((Int128)reader.ReadUInt64(), null),
            CborReaderState.NegativeInteger => (-1 - (Int128)reader.ReadCborNegativeIntegerRepresentation(), null),
            CborReaderState.TextString => (Int128.Zero, reader.ReadTextString()),
            CborReaderState otherState => throw new CborContentException(
                $"A COSE_Key label is an integer or a text string; the map carries a {otherState} map key (RFC 9052 Section 1.5).")
        };
    }
}
