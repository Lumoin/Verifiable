using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// CBOR reader for COSE_Key (RFC 9052 §7) producing the format-agnostic
/// <see cref="MdocCoseKey"/> view used by the MSO <c>DeviceKeyInfo</c>
/// substructure.
/// </summary>
/// <remarks>
/// <para>
/// COSE_Key is an integer-keyed CBOR map per RFC 9052 §7.1. The reader
/// recognises the common parameters
/// (<see cref="MdocCoseKeyParameters.Kty"/>, <see cref="MdocCoseKeyParameters.Alg"/>,
/// <see cref="MdocCoseKeyParameters.Crv"/>, <see cref="MdocCoseKeyParameters.X"/>,
/// <see cref="MdocCoseKeyParameters.Y"/>) and copies the byte-string fields
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
    /// <returns>The parsed <see cref="MdocCoseKey"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the bytes are not a valid CBOR map or when the
    /// mandatory <see cref="MdocCoseKeyParameters.Kty"/> parameter is missing.
    /// </exception>
    public static MdocCoseKey Read(ReadOnlySpan<byte> encodedCoseKey)
    {
        var reader = new CborReader(encodedCoseKey.ToArray(), CborConformanceMode.Lax);
        return ReadFromReader(reader);
    }


    /// <summary>
    /// Reads a COSE_Key from an existing <see cref="CborReader"/> positioned
    /// at the start of the map. Useful when composing parses (e.g.
    /// <see cref="MdocCborMsoReader"/> reading the <c>deviceKey</c> field
    /// from inside the MSO <c>DeviceKeyInfo</c> map).
    /// </summary>
    public static MdocCoseKey ReadFromReader(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        int? entryCount = reader.ReadStartMap();

        int? kty = null;
        int? alg = null;
        int? curve = null;
        ReadOnlyMemory<byte>? x = null;
        ReadOnlyMemory<byte>? y = null;
        bool? encodedYCompressionSign = null;

        int entriesRead = 0;
        while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            int label = (int)reader.ReadInt64();
            entriesRead++;

            switch(label)
            {
                case MdocCoseKeyParameters.Kty:
                {
                    kty = (int)reader.ReadInt64();

                    break;
                }
                case MdocCoseKeyParameters.Alg:
                {
                    alg = (int)reader.ReadInt64();

                    break;
                }
                case MdocCoseKeyParameters.Crv:
                {
                    curve = (int)reader.ReadInt64();

                    break;
                }
                case MdocCoseKeyParameters.X:
                {
                    x = reader.ReadByteString();

                    break;
                }
                case MdocCoseKeyParameters.Y:
                {
                    //Y is either a byte string (uncompressed coordinate) or a
                    //bool (compressed sign). Probe the next state to choose.
                    if(reader.PeekState() == CborReaderState.Boolean)
                    {
                        encodedYCompressionSign = reader.ReadBoolean();
                    }
                    else
                    {
                        y = reader.ReadByteString();
                    }

                    break;
                }
                default:
                {
                    //Unknown / unrequested labels are skipped per COSE forward-compat.
                    reader.SkipValue();

                    break;
                }
            }
        }

        reader.ReadEndMap();

        if(kty is null)
        {
            throw new CborContentException(
                "COSE_Key is missing the mandatory kty (1) parameter per RFC 9052 §7.1.");
        }

        return new MdocCoseKey(
            kty: kty.Value,
            alg: alg,
            curve: curve,
            x: x,
            y: y,
            encodedYCompressionSign: encodedYCompressionSign);
    }
}
