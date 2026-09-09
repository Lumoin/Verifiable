using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.StatusList;
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
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        CborValueConverter.WriteValue(writer, claims);

        return buffer.WrittenSpan;
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


    /// <summary>
    /// Builds the Status CBOR structure a COSE-based Referenced Token carries under CWT claim key
    /// <see cref="StatusListCborConstants.Status"/>, naming <c>status_list</c> as its one mechanism.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>: "status_list (status list): REQUIRED when the status mechanism
    /// defined in this specification is used. It has the same definition as the status_list claim in
    /// Section 6.2 but MUST be encoded as a StatusListInfo CBOR structure with the following fields:
    /// idx: REQUIRED. Unsigned integer (major type 0). ... uri: REQUIRED. Text string (major type 3)."
    /// </summary>
    /// <param name="index">The <c>idx</c> value, the entry to read in the Status List.</param>
    /// <param name="uri">The <c>uri</c> value, identifying the Status List Token.</param>
    /// <returns>The Status structure, ready to ride a CWT claim map.</returns>
    internal static Dictionary<string, object> BuildStatusWithStatusList(int index, string uri) =>
        BuildStatusWithRawStatusList(index, uri);


    /// <summary>
    /// <see cref="BuildStatusWithStatusList"/> with the <c>idx</c> and <c>uri</c> members written exactly
    /// as supplied, so a caller can state a StatusListInfo shape outside
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see>'s value domain: a text-string <c>idx</c> where "Unsigned integer
    /// (major type 0)" is REQUIRED, or a <c>uri</c> that is not "a URI conforming to [RFC3986]".
    /// </summary>
    /// <param name="index">The value written under <c>idx</c>, whatever its CBOR major type.</param>
    /// <param name="uri">The value written under <c>uri</c>, whatever its CBOR major type.</param>
    /// <returns>The Status structure carrying that <c>status_list</c> value.</returns>
    internal static Dictionary<string, object> BuildStatusWithRawStatusList(object index, object uri) =>
        new(StringComparer.Ordinal)
        {
            [StatusMechanismNames.StatusList] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [StatusListCborConstants.Index] = index,
                [StatusListCborConstants.Uri] = uri
            }
        };


    /// <summary>
    /// Builds a Status CBOR structure whose one mechanism is <c>identifier_list</c> — a mechanism this
    /// library records by name and does not evaluate, so the structure carries no <c>status_list</c>
    /// entry. The draft EU implementing act amending the EAA implementing regulations states: "When
    /// implementing the identifier list mechanism, the status element shall contain the identifier_list
    /// element as set out in EAA-6.2.10.1-11."
    /// </summary>
    /// <param name="identifier">The value written under the mechanism's own <c>id</c> member.</param>
    /// <returns>The Status structure naming that one mechanism.</returns>
    internal static Dictionary<string, object> BuildStatusWithIdentifierList(string identifier) =>
        new(StringComparer.Ordinal)
        {
            [StatusMechanismNames.IdentifierList] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["id"] = identifier
            }
        };


    /// <summary>
    /// Builds a Status CBOR structure carrying no data item at all, the shape
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see> forbids: "The Status CBOR structure is a Map that MUST include at
    /// least one data item that refers to a status mechanism."
    /// </summary>
    /// <returns>The empty Status structure.</returns>
    internal static Dictionary<string, object> BuildStatusWithNoMechanism() =>
        new(StringComparer.Ordinal);
}
