using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// Redacts selectively disclosable claims from a credential JSON document,
/// producing a ready-to-sign <see cref="JwtPayload"/> with <c>_sd</c> digest arrays
/// embedded at the correct nesting levels and the corresponding <see cref="SdDisclosure"/> list.
/// </summary>
/// <remarks>
/// <para>
/// This is the JSON-specific implementation of the selective disclosure redaction pipeline.
/// It composes the format-agnostic phases from <see cref="DisclosurePathGrouping"/> and
/// <see cref="DigestPlacement"/> with JSON-specific tree walking and value extraction.
/// </para>
/// <para>
/// The issuance pipeline for selective disclosure consists of three phases:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Group paths</strong> (<see cref="DisclosurePathGrouping.GroupByParent"/>):
/// Groups disclosable <see cref="CredentialPath"/> values by parent, determining where
/// each <c>_sd</c> array must be placed. Format-agnostic, shared with SD-CWT.
/// </description></item>
/// <item><description>
/// <strong>Walk and redact</strong> (this class): Walks the JSON document, creates
/// <see cref="SdDisclosure"/> objects for disclosable claims, computes digests, and
/// builds the mandatory claims tree. Format-specific (JSON).
/// </description></item>
/// <item><description>
/// <strong>Place digests</strong> (<see cref="DigestPlacement.PlaceDigests"/>):
/// Navigates the mandatory claims dictionary tree by <see cref="CredentialPath"/> and
/// inserts <c>_sd</c> arrays at each parent location. Format-agnostic, shared with SD-CWT.
/// </description></item>
/// </list>
/// <para>
/// This is the issuance-side complement of <see cref="SdJwtPathExtraction"/>.
/// Where <see cref="SdJwtPathExtraction.ExtractPaths"/> reads an already-issued
/// SD-JWT token and maps disclosures to paths, this class takes an unsigned
/// credential and splits it into a payload with embedded digests and disclosures.
/// </para>
/// <code>
/// Issuance direction (this class):
///   credential JSON + disclosable paths  ->  JwtPayload (with nested _sd) + List&lt;SdDisclosure&gt;
///
/// Extraction direction (SdJwtPathExtraction):
///   SdJwtToken  ->  Dictionary&lt;SdDisclosure, CredentialPath&gt;
/// </code>
/// <para>
/// <strong>Nested disclosure placement:</strong> Per
/// <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1">RFC 9901 Section 5.1</see>,
/// the <c>_sd</c> digest array is a sibling of the claims it replaces. For a disclosable path
/// like <c>/credentialSubject/degree</c>, the digest appears inside the <c>credentialSubject</c>
/// object's <c>_sd</c> array, not at the payload root. This class handles arbitrary nesting
/// depths correctly through the three-phase pipeline.
/// </para>
/// </remarks>
public static class SdJwtClaimRedaction
{
    /// <summary>
    /// Splits a credential JSON document into mandatory claims and disclosures
    /// without computing digests or placing <c>_sd</c> arrays.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This overload performs only Phase 1 (path grouping) and Phase 2 (walk and redact),
    /// skipping Phase 3 (digest placement). The returned payload contains only mandatory
    /// claims — no <c>_sd</c> or <c>_sd_alg</c>. This is useful for testing partition
    /// correctness independently of the digest pipeline.
    /// </para>
    /// <para>
    /// For a ready-to-sign payload with embedded <c>_sd</c> digest arrays, use the
    /// full overload that accepts serialization and digest delegates.
    /// </para>
    /// </remarks>
    /// <param name="credentialJson">The credential as a JSON string.</param>
    /// <param name="disclosablePaths">Paths to claims that should become selectively disclosable.</param>
    /// <param name="generateSalt">
    /// Delegate that allocates and fills a <see cref="Salt"/> per disclosable claim. Each
    /// returned <see cref="Salt"/>'s ownership transfers to the disclosure produced from
    /// it; if redaction fails partway through, the partially-built disclosures are
    /// disposed before the exception propagates.
    /// </param>
    /// <returns>
    /// A tuple containing the mandatory claims payload (without <c>_sd</c>) and the disclosures.
    /// Caller owns the returned disclosures and must dispose each (typically by handing
    /// them to an <see cref="SdToken{TEnvelope}"/> whose disposal flows to them).
    /// </returns>
    public static (JwtPayload Payload, IReadOnlyList<SdDisclosure> Disclosures) Redact(
        string credentialJson,
        IReadOnlySet<CredentialPath> disclosablePaths,
        GenerateDisclosureSaltDelegate generateSalt)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentialJson);
        ArgumentNullException.ThrowIfNull(disclosablePaths);
        ArgumentNullException.ThrowIfNull(generateSalt);

        using JsonDocument doc = JsonDocument.Parse(credentialJson);
        JsonElement root = doc.RootElement;

        if(root.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("Credential JSON must be a JSON object.", nameof(credentialJson));
        }

        //Phase 1: Group disclosable paths by parent.
        IReadOnlyDictionary<CredentialPath, IReadOnlySet<string>> groupedPaths =
            DisclosurePathGrouping.GroupByParent(disclosablePaths);

        //Phase 2: Walk JSON tree, create disclosures, build mandatory claims.
        //Digest computation is skipped — digestsByParent is not used.
        var allDisclosures = new List<SdDisclosure>();
        var digestsByParent = new Dictionary<CredentialPath, List<string>>();
        var payload = new JwtPayload();

        try
        {
            WalkObject(
                root,
                CredentialPath.Root,
                groupedPaths,
                generateSalt,
                serializeDisclosure: null,
                computeDigest: null,
                encoder: null,
                hashAlgorithm: null,
                payload,
                allDisclosures,
                digestsByParent);
        }
        catch
        {
            //If walking fails partway through, dispose every disclosure that was
            //already added. The caller never received them; we own them here.
            foreach(SdDisclosure d in allDisclosures)
            {
                d.Dispose();
            }
            throw;
        }

        //Phase 3 skipped — no _sd or _sd_alg placement.

        return (payload, allDisclosures);
    }


    /// <summary>
    /// Splits a credential JSON document into a payload with embedded <c>_sd</c> digest arrays
    /// and a list of selectively disclosable claims.
    /// </summary>
    /// <param name="credentialJson">
    /// The credential as a JSON string. Both flat (SD-JWT VC with <c>iss</c>, <c>vct</c>)
    /// and nested (W3C VC with <c>credentialSubject</c>) structures are handled correctly.
    /// </param>
    /// <param name="disclosablePaths">
    /// Paths to claims that should become selectively disclosable.
    /// </param>
    /// <param name="generateSalt">
    /// Delegate that allocates and fills a <see cref="Salt"/> per disclosable claim.
    /// Each returned <see cref="Salt"/>'s ownership transfers to the disclosure produced
    /// from it; if redaction fails partway through, the partially-built disclosures are
    /// disposed before the exception propagates.
    /// </param>
    /// <param name="serializeDisclosure">
    /// Delegate for serializing a disclosure to its Base64Url-encoded form.
    /// </param>
    /// <param name="computeDigest">
    /// Delegate for computing the digest of an encoded disclosure.
    /// </param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format (e.g., <c>"sha-256"</c>).
    /// </param>
    /// <param name="decoyOptions">
    /// Optional decoy-digest configuration (count policy plus per-call state) per RFC 9901 §4.2.5,
    /// applied once per <c>_sd</c> location. <see cref="DecoyDigestOptions.None"/> (the default) means no decoys. A decoy is the same
    /// digest function applied to fresh random bytes, so it is indistinguishable from a real digest and
    /// is ignored by verifiers.
    /// </param>
    /// <returns>
    /// A tuple containing the ready-to-sign payload and the disclosures. Caller owns
    /// the returned disclosures and must dispose each.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="credentialJson"/> is not a JSON object.
    /// </exception>
    public static (JwtPayload Payload, IReadOnlyList<SdDisclosure> Disclosures) Redact(
        string credentialJson,
        IReadOnlySet<CredentialPath> disclosablePaths,
        GenerateDisclosureSaltDelegate generateSalt,
        SerializeDisclosureDelegate<SdDisclosure> serializeDisclosure,
        ComputeDisclosureDigestDelegate computeDigest,
        EncodeDelegate encoder,
        string hashAlgorithm,
        DecoyDigestOptions decoyOptions = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentialJson);
        ArgumentNullException.ThrowIfNull(disclosablePaths);
        ArgumentNullException.ThrowIfNull(generateSalt);
        ArgumentNullException.ThrowIfNull(serializeDisclosure);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithm);

        DecoyDigestCountDelegate resolvedDecoyCount = decoyOptions.Count ?? DecoyDigestPolicy.None;
        object? decoyState = decoyOptions.State;

        using JsonDocument doc = JsonDocument.Parse(credentialJson);
        JsonElement root = doc.RootElement;

        if(root.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("Credential JSON must be a JSON object.", nameof(credentialJson));
        }

        //Phase 1: Group disclosable paths by parent using CredentialPath structure.
        IReadOnlyDictionary<CredentialPath, IReadOnlySet<string>> groupedPaths =
            DisclosurePathGrouping.GroupByParent(disclosablePaths);

        //Phase 2: Walk JSON tree, create disclosures, compute digests, build mandatory claims.
        var allDisclosures = new List<SdDisclosure>();
        var digestsByParent = new Dictionary<CredentialPath, List<string>>();
        var payload = new JwtPayload();

        try
        {
            WalkObject(
                root,
                CredentialPath.Root,
                groupedPaths,
                generateSalt,
                serializeDisclosure,
                computeDigest,
                encoder,
                hashAlgorithm,
                payload,
                allDisclosures,
                digestsByParent);

            //Phase 2b (optional): pad each _sd location with decoy digests (RFC 9901 §4.2.5).
            //A decoy is the same digest function over fresh random bytes — indistinguishable
            //from a real digest and ignored by verifiers. Inside the try so a failure here still
            //disposes the disclosures created above.
            DecoyDigests.Augment(digestsByParent, resolvedDecoyCount, decoyState, MakeDecoyDigest);
        }
        catch
        {
            //If walking fails partway through, dispose every disclosure that was
            //already added. The caller never received them; we own them here.
            foreach(SdDisclosure d in allDisclosures)
            {
                d.Dispose();
            }
            throw;
        }

        //Phase 3: Place _sd arrays at the correct locations and add _sd_alg.
        DigestPlacement.PlaceDigests(payload, digestsByParent, hashAlgorithm);

        return (payload, allDisclosures);

        //Produces one decoy digest: Base64Url(Hash(Base64Url(random salt bytes))) — the same
        //pipeline a real disclosure digest goes through, over random bytes instead of a disclosure.
        //The decoy salt backs no disclosure, so this owns and disposes it.
        string MakeDecoyDigest()
        {
            using Salt decoySalt = generateSalt();
            string randomEncoded = encoder(decoySalt.AsReadOnlySpan());

            return computeDigest(randomEncoded, hashAlgorithm, encoder);
        }
    }


    /// <summary>
    /// Recursively walks a JSON object, separating mandatory claims from disclosable ones.
    /// </summary>
    private static void WalkObject(
        JsonElement element,
        CredentialPath currentPath,
        IReadOnlyDictionary<CredentialPath, IReadOnlySet<string>> groupedPaths,
        GenerateDisclosureSaltDelegate generateSalt,
        SerializeDisclosureDelegate<SdDisclosure>? serializeDisclosure,
        ComputeDisclosureDigestDelegate? computeDigest,
        EncodeDelegate? encoder,
        string? hashAlgorithm,
        Dictionary<string, object> mandatoryOutput,
        List<SdDisclosure> allDisclosures,
        Dictionary<CredentialPath, List<string>> digestsByParent)
    {
        //Check if this level has disclosable claims.
        groupedPaths.TryGetValue(currentPath, out IReadOnlySet<string>? disclosableAtThisLevel);

        foreach(JsonProperty prop in element.EnumerateObject())
        {
            if(disclosableAtThisLevel is not null && disclosableAtThisLevel.Contains(prop.Name))
            {
                //This property is disclosable — generate salt, create disclosure, compute digest.
                //Salt ownership transfers into SdDisclosure.CreateProperty; CreateProperty
                //disposes the salt on construction failure (e.g., null/empty claim name).
                object? value = JsonElementConversion.Convert(prop.Value);
                Salt salt = generateSalt();
                SdDisclosure disclosure = SdDisclosure.CreateProperty(salt, prop.Name, value);
                allDisclosures.Add(disclosure);

                if(serializeDisclosure is not null && computeDigest is not null && encoder is not null)
                {
                    string encoded = serializeDisclosure(disclosure, encoder);
                    string digest = computeDigest(encoded, hashAlgorithm!, encoder);

                    if(!digestsByParent.TryGetValue(currentPath, out List<string>? digests))
                    {
                        digests = [];
                        digestsByParent[currentPath] = digests;
                    }

                    digests.Add(digest);
                }
            }
            else if(prop.Value.ValueKind == JsonValueKind.Object)
            {
                CredentialPath childPath = currentPath.Append(prop.Name);

                if(DisclosurePathGrouping.HasDisclosableDescendants(childPath, groupedPaths))
                {
                    //Recurse into nested object that contains disclosable descendants.
                    var nestedOutput = new Dictionary<string, object>();
                    WalkObject(
                        prop.Value,
                        childPath,
                        groupedPaths,
                        generateSalt,
                        serializeDisclosure,
                        computeDigest,
                        encoder,
                        hashAlgorithm,
                        nestedOutput,
                        allDisclosures,
                        digestsByParent);

                    mandatoryOutput[prop.Name] = nestedOutput;
                }
                else
                {
                    //No disclosable descendants — copy entire subtree as-is.
                    mandatoryOutput[prop.Name] = JsonElementConversion.Convert(prop.Value)!;
                }
            }
            else
            {
                //Mandatory scalar or array claim — copy as-is.
                mandatoryOutput[prop.Name] = JsonElementConversion.Convert(prop.Value)!;
            }
        }
    }
}
