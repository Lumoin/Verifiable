using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared CWT claim-map wire assembly for the SD-CWT issuance, key-binding, presentation, and
/// verification test corpus spanning <c>FlowTests</c>, <c>OAuth</c>, and <c>SelectiveDisclosure</c>.
/// </summary>
internal static class SdCwtWireFixtures
{
    /// <summary>Canonical-CBOR-encodes a CWT claim map (integer claim keys).</summary>
    /// <param name="claims">The claim map, keyed by CWT/COSE integer claim label.</param>
    /// <returns>The canonical CBOR encoding.</returns>
    internal static ReadOnlySpan<byte> SerializeCwtClaimMap(Dictionary<int, object> claims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        CborValueConverter.WriteValue(writer, claims);

        return writer.Encode();
    }


    /// <summary>
    /// Builds a <c>cnf</c> claim map carrying <paramref name="holderPublic"/> as a P-256 EC2 COSE_Key
    /// (<c>kty=2, crv=1</c>), decompressing the stored compressed public key to recover <c>y</c>.
    /// </summary>
    /// <param name="holderPublic">The holder's P-256 public key, stored compressed.</param>
    /// <param name="cnfClaimKey">The integer claim label the <c>cnf</c> map is keyed under.</param>
    /// <returns>A single-entry claim map: <c>{cnfClaimKey: coseKeyMap}</c>.</returns>
    internal static Dictionary<int, object> BuildCnfWithHolderKey(PublicKeyMemory holderPublic, int cnfClaimKey)
    {
        ReadOnlySpan<byte> compressed = holderPublic.AsReadOnlySpan();
        byte[] x = compressed[1..].ToArray();
        byte[] y = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);

        var coseKey = new Dictionary<int, object>
        {
            [1] = 2,   //kty = EC2.
            [-1] = 1,  //crv = P-256.
            [-2] = x,  //x coordinate.
            [-3] = y   //y coordinate.
        };

        return new Dictionary<int, object> { [cnfClaimKey] = coseKey };
    }
}
