using System.Formats.Cbor;
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
    /// Thrown when the bytes are not a valid CBOR map or when the
    /// mandatory <see cref="CoseKeyParameters.Kty"/> parameter is missing.
    /// </exception>
    public static CoseKey Read(ReadOnlySpan<byte> encodedCoseKey) => Read(encodedCoseKey, out _);


    /// <summary>
    /// Reads a COSE_Key from the supplied CBOR bytes, additionally reporting the top-level integer
    /// labels encountered while parsing it.
    /// </summary>
    /// <param name="encodedCoseKey">The CBOR-encoded COSE_Key bytes.</param>
    /// <param name="labels">
    /// Receives the top-level integer labels encountered while parsing, in wire order, including
    /// duplicates if the wire bytes carried any.
    /// </param>
    /// <returns>The parsed <see cref="CoseKey"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the bytes are not a valid CBOR map or when the
    /// mandatory <see cref="CoseKeyParameters.Kty"/> parameter is missing.
    /// </exception>
    public static CoseKey Read(ReadOnlySpan<byte> encodedCoseKey, out IReadOnlyList<int> labels)
    {
        var reader = new CborReader(encodedCoseKey.ToArray(), CborConformanceMode.Lax);
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
    public static CoseKey ReadFromReader(CborReader reader) => ReadFromReader(reader, out _);


    /// <summary>
    /// Reads a COSE_Key from an existing <see cref="CborReader"/> positioned at the start of the map,
    /// additionally reporting the top-level integer labels encountered while parsing it.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the start of the COSE_Key map.</param>
    /// <param name="labels">
    /// Receives the top-level integer labels encountered while parsing, in wire order, including
    /// duplicates if the wire bytes carried any.
    /// </param>
    /// <returns>The parsed <see cref="CoseKey"/>.</returns>
    public static CoseKey ReadFromReader(CborReader reader, out IReadOnlyList<int> labels)
    {
        ArgumentNullException.ThrowIfNull(reader);

        int? entryCount = reader.ReadStartMap();

        int? kty = null;
        int? alg = null;
        int? curve = null;
        ReadOnlyMemory<byte>? x = null;
        ReadOnlyMemory<byte>? y = null;
        bool? encodedYCompressionSign = null;
        var encounteredLabels = new List<int>();

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            int label = (int)reader.ReadInt64();
            entriesRead++;
            encounteredLabels.Add(label);

            _ = label switch
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
            kty = (int)reader.ReadInt64();

            return true;
        }

        //Assigns the decoded algorithm identifier to alg.
        static bool AssignAlg(CborReader reader, ref int? alg)
        {
            alg = (int)reader.ReadInt64();

            return true;
        }

        //Assigns the decoded curve identifier to curve.
        static bool AssignCrv(CborReader reader, ref int? curve)
        {
            curve = (int)reader.ReadInt64();

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
}
