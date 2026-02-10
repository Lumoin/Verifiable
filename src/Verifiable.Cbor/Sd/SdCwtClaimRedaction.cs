using System.Formats.Cbor;
using System.Globalization;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// Redacts selectively disclosable claims from a CBOR-encoded CWT payload,
/// producing a <see cref="CwtPayload"/> with <c>redacted_claim_keys</c> digest arrays
/// and the corresponding <see cref="SdDisclosure"/> list.
/// </summary>
/// <remarks>
/// <para>
/// This is the CBOR-specific implementation of the selective disclosure redaction pipeline,
/// the CWT parallel of <c>SdJwtClaimRedaction</c> in <c>Verifiable.Json</c>.
/// </para>
/// <para>
/// The issuance pipeline for SD-CWT consists of three phases:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Group paths</strong> (<see cref="DisclosurePathGrouping.GroupByParent"/>):
/// Groups disclosable <see cref="CredentialPath"/> values by parent, determining where
/// each <c>redacted_claim_keys</c> array must be placed. Format-agnostic, shared with SD-JWT.
/// </description></item>
/// <item><description>
/// <strong>Walk and redact</strong> (this class): Walks the CBOR map, creates
/// <see cref="SdDisclosure"/> objects for disclosable claims, serializes them via
/// <see cref="SdCwtSerializer.SerializeDisclosure(SdDisclosure)"/>, computes digests via
/// <see cref="SdCwtSerializer.ComputeDisclosureDigest(byte[], string)"/>, and builds the
/// mandatory claims tree. Format-specific (CBOR).
/// </description></item>
/// <item><description>
/// <strong>Place digests</strong> (<see cref="CwtDigestPlacement.PlaceDigests"/>):
/// Navigates the mandatory claims dictionary tree by <see cref="CredentialPath"/> and
/// inserts <c>redacted_claim_keys</c> arrays at each parent location. Format-specific (CWT).
/// </description></item>
/// </list>
/// <para>
/// Per <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>, redacted map entries have their blinded claim hashes placed
/// under the CBOR <c>simple(59)</c> key as an array of <c>bstr</c> values at the same
/// level of hierarchy. The <c>sd_alg</c> parameter goes into the COSE protected header,
/// not the payload.
/// </para>
/// <para>
/// Unlike the SD-JWT side which uses delegates for serialization and digest computation
/// (because the Base64Url encoder varies by context), the CWT side calls
/// <see cref="SdCwtSerializer"/> directly. CWT serialization always uses CTAP2 canonical
/// CBOR encoding and produces raw hash bytes, so there is no variability to abstract.
/// </para>
/// </remarks>
public static class SdCwtClaimRedaction
{
    /// <summary>
    /// Splits a CBOR-encoded CWT payload into mandatory claims and disclosures,
    /// with digests placed in <c>redacted_claim_keys</c> arrays.
    /// </summary>
    /// <param name="cwtPayloadBytes">
    /// The CBOR-encoded CWT claims map. Must be a CBOR map with integer keys.
    /// </param>
    /// <param name="disclosablePaths">
    /// Paths to claims that should become selectively disclosable. For CWT, path segments
    /// are string representations of integer claim keys (e.g., <c>/501</c> for claim key 501).
    /// </param>
    /// <param name="saltFactory">
    /// Factory for generating cryptographic salt bytes for each disclosure.
    /// </param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format (e.g., <c>"sha-256"</c>).
    /// </param>
    /// <returns>
    /// A tuple containing the mandatory claims payload (with <c>redacted_claim_keys</c>
    /// arrays at the correct locations) and the list of disclosures.
    /// </returns>
    public static (CwtPayload Payload, IReadOnlyList<SdDisclosure> Disclosures) Redact(
        byte[] cwtPayloadBytes,
        IReadOnlySet<CredentialPath> disclosablePaths,
        SaltFactoryDelegate saltFactory,
        string hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(cwtPayloadBytes);
        ArgumentNullException.ThrowIfNull(disclosablePaths);
        ArgumentNullException.ThrowIfNull(saltFactory);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithm);

        //Phase 1: Group disclosable paths by parent.
        IReadOnlyDictionary<CredentialPath, IReadOnlySet<string>> groupedPaths =
            DisclosurePathGrouping.GroupByParent(disclosablePaths);

        //Phase 2: Walk CWT map, create disclosures, compute digests, build mandatory claims.
        var allDisclosures = new List<SdDisclosure>();
        var digestsByParent = new Dictionary<CredentialPath, List<byte[]>>();
        var payload = new CwtPayload();

        var reader = new CborReader(cwtPayloadBytes, CborConformanceMode.Lax);
        WalkMap(
            ref reader,
            CredentialPath.Root,
            groupedPaths,
            saltFactory,
            hashAlgorithm,
            payload,
            allDisclosures,
            digestsByParent);

        //Phase 3: Place redacted_claim_keys arrays at the correct locations.
        CwtDigestPlacement.PlaceDigests(payload, digestsByParent);

        return (payload, allDisclosures);
    }


    /// <summary>
    /// Recursively walks a CBOR map, separating mandatory claims from disclosable ones.
    /// </summary>
    private static void WalkMap(
        ref CborReader reader,
        CredentialPath currentPath,
        IReadOnlyDictionary<CredentialPath, IReadOnlySet<string>> groupedPaths,
        SaltFactoryDelegate saltFactory,
        string hashAlgorithm,
        Dictionary<int, object> mandatoryOutput,
        List<SdDisclosure> allDisclosures,
        Dictionary<CredentialPath, List<byte[]>> digestsByParent)
    {
        //Check if this level has disclosable claims.
        groupedPaths.TryGetValue(currentPath, out IReadOnlySet<string>? disclosableAtThisLevel);

        int? mapCount = reader.ReadStartMap();

        int itemsRead = 0;
        while(mapCount is null ? reader.PeekState() != CborReaderState.EndMap : itemsRead < mapCount)
        {
            //CWT maps use integer keys.
            int key = reader.ReadInt32();
            string keyString = key.ToString(CultureInfo.InvariantCulture);

            if(disclosableAtThisLevel is not null && disclosableAtThisLevel.Contains(keyString))
            {
                //This claim is disclosable — read value, create disclosure, compute digest.
                object? value = CborValueConverter.ReadValue(ref reader);
                byte[] salt = saltFactory();
                SdDisclosure disclosure = SdDisclosure.CreateProperty(salt, keyString, value);
                allDisclosures.Add(disclosure);

                byte[] encoded = SdCwtSerializer.SerializeDisclosure(disclosure);
                byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(encoded, hashAlgorithm);

                if(!digestsByParent.TryGetValue(currentPath, out List<byte[]>? digests))
                {
                    digests = [];
                    digestsByParent[currentPath] = digests;
                }

                digests.Add(digest);
            }
            else if(reader.PeekState() == CborReaderState.StartMap)
            {
                CredentialPath childPath = currentPath.Append(keyString);

                if(DisclosurePathGrouping.HasDisclosableDescendants(childPath, groupedPaths))
                {
                    //Recurse into nested map that contains disclosable descendants.
                    var nestedOutput = new Dictionary<int, object>();
                    WalkMap(
                        ref reader,
                        childPath,
                        groupedPaths,
                        saltFactory,
                        hashAlgorithm,
                        nestedOutput,
                        allDisclosures,
                        digestsByParent);

                    mandatoryOutput[key] = nestedOutput;
                }
                else
                {
                    //No disclosable descendants — copy entire subtree as-is.
                    mandatoryOutput[key] = CborValueConverter.ReadValue(ref reader)!;
                }
            }
            else
            {
                //Mandatory scalar, array, or other value — copy as-is.
                mandatoryOutput[key] = CborValueConverter.ReadValue(ref reader)!;
            }

            itemsRead++;
        }

        reader.ReadEndMap();
    }
}