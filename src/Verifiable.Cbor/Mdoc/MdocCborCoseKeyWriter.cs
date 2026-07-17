using System.Formats.Cbor;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Writes a <see cref="CoseKey"/> to its on-wire CBOR map per
/// RFC 9052 §7.1. Paired with <see cref="MdocCborCoseKeyReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// Emits only the parameters the parsed view carries (kty + optional alg /
/// crv / x / y). Canonical conformance mode sorts the integer keys per
/// RFC 8949 §4.2.1 so the encoded bytes are deterministic for any given
/// parsed view.
/// </para>
/// </remarks>
public static class MdocCborCoseKeyWriter
{
    /// <summary>
    /// Encodes <paramref name="coseKey"/> as a CBOR map.
    /// </summary>
    /// <returns>The CBOR-encoded COSE_Key bytes.</returns>
    public static ReadOnlyMemory<byte> Write(CoseKey coseKey)
    {
        ArgumentNullException.ThrowIfNull(coseKey);

        var writer = new CborWriter(CborConformanceMode.Canonical);

        int entryCount = CountEntries(coseKey);

        writer.WriteStartMap(entryCount);

        //CborWriter in canonical mode sorts the keys for us — the order they
        //appear here is irrelevant. RFC 8949 §4.2.1 says int keys sort by
        //numeric value; the emitted order will be ascending.
        writer.WriteInt32(CoseKeyParameters.Kty);
        writer.WriteInt32(coseKey.Kty);

        if(coseKey.Alg is int alg)
        {
            writer.WriteInt32(CoseKeyParameters.Alg);
            writer.WriteInt32(alg);
        }

        if(coseKey.Curve is int curve)
        {
            writer.WriteInt32(CoseKeyParameters.Crv);
            writer.WriteInt32(curve);
        }

        if(coseKey.X is ReadOnlyMemory<byte> x)
        {
            writer.WriteInt32(CoseKeyParameters.X);
            writer.WriteByteString(x.Span);
        }

        if(coseKey.Y is ReadOnlyMemory<byte> y)
        {
            writer.WriteInt32(CoseKeyParameters.Y);
            writer.WriteByteString(y.Span);
        }
        else if(coseKey.EncodedYCompressionSign is bool sign)
        {
            writer.WriteInt32(CoseKeyParameters.Y);
            writer.WriteBoolean(sign);
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    private static int CountEntries(CoseKey coseKey)
    {
        int count = 1; //kty is required.

        if(coseKey.Alg is not null)
        {
            count++;
        }

        if(coseKey.Curve is not null)
        {
            count++;
        }

        if(coseKey.X is not null)
        {
            count++;
        }

        if(coseKey.Y is not null || coseKey.EncodedYCompressionSign is not null)
        {
            count++;
        }

        return count;
    }
}
