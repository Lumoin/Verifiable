using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Adapter that plugs a parsed <see cref="SdToken{TEnvelope}"/> into the
/// format-agnostic <see cref="DcqlEvaluator"/>, exposing the two extension
/// points the evaluator consumes — <see cref="DcqlMetadataExtractor{TCredential}"/>
/// and <see cref="DcqlClaimExtractor{TCredential}"/>. One adapter serves both
/// SD-JWT VC (<c>SdToken&lt;string&gt;</c>) and SD-CWT
/// (<c>SdToken&lt;ReadOnlyMemory&lt;byte&gt;&gt;</c>).
/// </summary>
/// <remarks>
/// <para>
/// Unlike <c>MdocDcqlAdapter</c> — which lives in the CBOR assembly because it
/// must CBOR-decode each element value — an <see cref="SdToken{TEnvelope}"/> parsed through
/// <c>SdJwtSerializer.ParseToken</c>/<c>SdCwtSerializer.ParseToken</c> already carries every
/// claim value it needs: <see cref="SdToken{TEnvelope}.DisclosurePaths"/> for what the holder
/// can selectively disclose, <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> for what is
/// unconditionally disclosed and <see cref="SdToken{TEnvelope}.DisclosureInteriorClaims"/> for
/// what a disclosure's release reveals. So both extractors operate purely on the token with no
/// serialization dependency, and this adapter lives in <c>Verifiable.Core</c> and is format-neutral.
/// </para>
/// <para>
/// The credential's type evidence comes from the token's own
/// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> — the credential's <c>vct</c> (defined in
/// SD-JWT VC §2.2.2.1) and <c>aka_vcts</c> (§2.2.2.2) claims, exactly as the verified issuer-signed
/// payload carries them. §2.2.2.3 is where <c>vct</c> is designated REQUIRED and <c>aka_vcts</c>
/// OPTIONAL, and both placed among the claims that "MUST NOT be included in the Disclosures", which
/// is why they are read from the unconditionally disclosed claims. There is no separate parameter
/// for either: a credential that carries none has none, and <see cref="DcqlEvaluator"/> fails the
/// corresponding constraint closed rather than being told to skip it. The trust evidence a
/// <c>trusted_authorities</c> constraint is matched against comes from the caller-supplied
/// <see cref="TrustedAuthorityEvidenceSource{TCredential}"/> instead — the token's own claims (an
/// <c>iss</c> string) are not themselves §6.1.1-typed evidence.
/// </para>
/// <para>
/// DCQL claim patterns resolve over the union of <see cref="SdToken{TEnvelope}.DisclosurePaths"/>,
/// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> and
/// <see cref="SdToken{TEnvelope}.DisclosureInteriorClaims"/> by
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.1.1">
/// OpenID for Verifiable Presentations 1.0 §7.1.1</see>'s processing rules — string, index, and
/// wildcard (<see langword="null"/>) path components at any depth, not just a single segment. The
/// union is what the credential can address: an interior node is addressable because the
/// disclosure that carries it can be released, which is what
/// <see cref="SdToken{TEnvelope}.SelectDisclosures(IReadOnlySet{CredentialPath}, BaseMemoryPool)"/>
/// then does when the wallet acts on the match.
/// </para>
/// </remarks>
public static class SdTokenDcqlAdapter
{
    /// <summary>
    /// Where a credential's type evidence sits among its issuer-signed claims. An SD-JWT VC keys it
    /// by the JWT claim names (<c>vct</c>, <c>aka_vcts</c>); an SD-CWT keys <c>vct</c> by the CWT
    /// claim key (<see cref="WellKnownCwtClaimNames.Vct"/>), which the SD-CWT parse carries as its
    /// decimal text. SD-JWT VC defines no CWT claim key for <c>aka_vcts</c>, so an SD-CWT declares no
    /// additional types.
    /// </summary>
    /// <param name="Vct">The path of the credential's <c>vct</c> claim.</param>
    /// <param name="AkaVcts">The path of the credential's <c>aka_vcts</c> claim, or <see langword="null"/> when the format defines none.</param>
    private readonly record struct EvidencePaths(CredentialPath Vct, CredentialPath? AkaVcts);

    /// <summary>The SD-JWT VC evidence paths: the root-level JWT claim names.</summary>
    private static EvidencePaths SdJwtEvidencePaths { get; } = new(
        CredentialPath.Root.Append(WellKnownJwtClaimNames.Vct),
        CredentialPath.Root.Append(WellKnownJwtClaimNames.AkaVcts));

    /// <summary>The SD-CWT evidence paths: the root-level CWT claim keys in decimal text.</summary>
    private static EvidencePaths SdCwtEvidencePaths { get; } = new(
        CredentialPath.Root.Append(WellKnownCwtClaimNames.Vct.ToString(CultureInfo.InvariantCulture)),
        null);


    /// <summary>
    /// Selects the evidence paths a DCQL format identifier implies: <see cref="DcqlCredentialFormats.SdCwt"/>
    /// reads the CWT claim keys, every other SD format the JWT claim names.
    /// </summary>
    /// <param name="format">The DCQL format identifier.</param>
    private static EvidencePaths EvidencePathsFor(string format) => format switch
    {
        var f when string.Equals(f, DcqlCredentialFormats.SdCwt, StringComparison.Ordinal) => SdCwtEvidencePaths,
        _ => SdJwtEvidencePaths
    };


    /// <summary>
    /// Builds a <see cref="DcqlMetadataExtractor{TCredential}"/> for an
    /// <see cref="SdToken{TEnvelope}"/>. <see cref="DcqlCredentialMetadata.CredentialType"/> and
    /// <see cref="DcqlCredentialMetadata.AdditionalTypes"/> come from the token's own
    /// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> (<c>vct</c> and <c>aka_vcts</c>
    /// respectively); <see cref="DcqlCredentialMetadata.TrustedAuthorityEvidence"/> comes from
    /// <paramref name="trustedAuthorityEvidence"/> when supplied;
    /// <see cref="DcqlCredentialMetadata.AvailablePaths"/> is the union of
    /// <see cref="SdToken{TEnvelope}.DisclosurePaths"/>,
    /// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> keys and
    /// <see cref="SdToken{TEnvelope}.DisclosureInteriorClaims"/> keys.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type (<c>string</c> for SD-JWT VC, <c>ReadOnlyMemory&lt;byte&gt;</c> for SD-CWT).</typeparam>
    /// <param name="format">
    /// The DCQL format identifier (<c>dc+sd-jwt</c> or <c>dc+sd-cwt</c>); it selects where the
    /// type evidence is read from (JWT claim names or CWT claim keys).
    /// </param>
    /// <param name="trustedAuthorityEvidence">
    /// Reads the token's cached OID4VP 1.0 §6.1.1 trust evidence, or <see langword="null"/> when the
    /// caller supplies none — a credential with no evidence fails a <c>trusted_authorities</c>
    /// constraint closed rather than being told to skip it.
    /// </param>
    public static DcqlMetadataExtractor<SdToken<TEnvelope>> CreateMetadataExtractor<TEnvelope>(
        string format,
        TrustedAuthorityEvidenceSource<SdToken<TEnvelope>>? trustedAuthorityEvidence = null)
        where TEnvelope : notnull
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(format);

        EvidencePaths evidence = EvidencePathsFor(format);

        return token =>
        {
            ArgumentNullException.ThrowIfNull(token);

            var availablePaths = new HashSet<CredentialPath>(token.DisclosurePaths.Paths);
            foreach(CredentialPath path in token.IssuerSignedClaims.Keys)
            {
                availablePaths.Add(path);
            }

            foreach(CredentialPath path in token.DisclosureInteriorClaims.Keys)
            {
                availablePaths.Add(path);
            }

            string? credentialType = token.IssuerSignedClaims.TryGetValue(evidence.Vct, out object? vct) ? vct as string : null;

            return new DcqlCredentialMetadata
            {
                Format = format,
                CredentialType = credentialType,
                AdditionalTypes = ExtractAdditionalTypes(token, evidence.AkaVcts),
                TrustedAuthorityEvidence = trustedAuthorityEvidence?.Invoke(token),
                AvailablePaths = availablePaths
            };
        };
    }


    /// <summary>
    /// Extracts the claim value at the given pattern from an <see cref="SdToken{TEnvelope}"/> by
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.1.1">
    /// OpenID for Verifiable Presentations 1.0 §7.1.1</see>: a concrete (wildcard-free) pattern
    /// resolves directly to a <see cref="CredentialPath"/> and is looked up in the union of
    /// <see cref="SdToken{TEnvelope}.DisclosurePaths"/> and
    /// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/>; a pattern with a <see langword="null"/>
    /// (wildcard) component is processed left to right, tracking the set of currently-selected
    /// paths and expanding a wildcard to every array-index child the union carries.
    /// </summary>
    /// <remarks>
    /// §7.1.1 distinguishes two outcomes and this adapter applies both, against the CLR shape of
    /// each selected node. A string component whose selection holds anything that is not an object
    /// ("If any of the currently selected element(s) is not an object, abort processing and return
    /// an error"), and a <see langword="null"/> or integer component whose selection holds anything
    /// that is not an array, abort. A component that merely addresses nothing in an admissible
    /// node — a key absent from an object, an index absent from an array — removes that element
    /// from the selection, and an empty selection is an error in its turn. Both outcomes reach the
    /// caller as no match, since this delegate has only a match/no-match result to report; what
    /// distinguishes them is that the abort case refuses a heterogeneous selection outright
    /// instead of quietly keeping the members that happened to fit.
    /// </remarks>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    public static bool ClaimExtractor<TEnvelope>(
        SdToken<TEnvelope> credential,
        DcqlClaimPattern pattern,
        out object? value)
        where TEnvelope : notnull
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(pattern);

        if(pattern.TryResolve(out CredentialPath concretePath))
        {
            return TryGetValue(credential, concretePath, out value);
        }

        return TryResolveWildcardPattern(credential, pattern, out value);
    }


    /// <summary>
    /// Reads the credential's <c>aka_vcts</c> claim (SD-JWT VC §2.2.2.2) into the additional-types
    /// evidence <see cref="DcqlEvaluator"/> answers <c>vct_values</c> inheritance against
    /// (Appendix B.3.5's MAY). Empty when the format defines no such claim or the credential
    /// carries none.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    /// <param name="token">The token whose issuer-signed claims are read.</param>
    /// <param name="akaVctsPath">The format's <c>aka_vcts</c> path, or <see langword="null"/> when it defines none.</param>
    private static HashSet<string> ExtractAdditionalTypes<TEnvelope>(SdToken<TEnvelope> token, CredentialPath? akaVctsPath)
        where TEnvelope : notnull
    {
        if(akaVctsPath is not CredentialPath path || !token.IssuerSignedClaims.TryGetValue(path, out object? akaVcts))
        {
            return new HashSet<string>();
        }

        var result = new HashSet<string>(StringComparer.Ordinal);
        if(akaVcts is IEnumerable<object?> values)
        {
            foreach(object? item in values)
            {
                if(item is string type)
                {
                    result.Add(type);
                }
            }
        }

        return result;
    }


    /// <summary>
    /// Looks up the value at a concrete path in the union of the token's disclosure paths,
    /// unconditionally disclosed claims and disclosure-interior claims — a disclosure path's value
    /// is the disclosure's own <see cref="SdDisclosure.ClaimValue"/>; any other addressable path's
    /// value comes from the claim map that carries it.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    /// <param name="credential">The token to look the path up in.</param>
    /// <param name="path">The concrete path to resolve.</param>
    /// <param name="value">The resolved value, when found.</param>
    /// <returns><see langword="true"/> when the path resolves to a value.</returns>
    private static bool TryGetValue<TEnvelope>(SdToken<TEnvelope> credential, CredentialPath path, out object? value)
        where TEnvelope : notnull
    {
        if(credential.DisclosurePaths.TryGetDisclosure(path, out SdDisclosure? disclosure))
        {
            value = disclosure.ClaimValue;

            return true;
        }

        if(credential.IssuerSignedClaims.TryGetValue(path, out value))
        {
            return true;
        }

        return credential.DisclosureInteriorClaims.TryGetValue(path, out value);
    }


    /// <summary>
    /// Whether a concrete path exists in the union of the token's disclosure paths,
    /// unconditionally disclosed claims and disclosure-interior claims.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    /// <param name="credential">The token to check.</param>
    /// <param name="path">The concrete path to check for.</param>
    private static bool IsAvailable<TEnvelope>(SdToken<TEnvelope> credential, CredentialPath path)
        where TEnvelope : notnull =>
        credential.DisclosurePaths.Paths.Contains(path)
        || credential.IssuerSignedClaims.ContainsKey(path)
        || credential.DisclosureInteriorClaims.ContainsKey(path);


    /// <summary>
    /// Implements the OpenID for Verifiable Presentations 1.0 §7.1.1 processing loop for a
    /// pattern that contains a wildcard component: tracks the set of currently-selected concrete
    /// paths and applies each component in turn, expanding a wildcard to every array-index child
    /// available.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    /// <param name="credential">The token to resolve the pattern against.</param>
    /// <param name="pattern">The wildcard-bearing pattern.</param>
    /// <param name="value">The resolved value (or, for more than one selected element, a list of values), when found.</param>
    /// <returns><see langword="true"/> when the pattern resolves to at least one value.</returns>
    private static bool TryResolveWildcardPattern<TEnvelope>(
        SdToken<TEnvelope> credential,
        DcqlClaimPattern pattern,
        out object? value)
        where TEnvelope : notnull
    {
        var selected = new HashSet<CredentialPath> { CredentialPath.Root };

        for(int i = 0; i < pattern.Count; i++)
        {
            PatternSegment segment = pattern[i];
            var next = new HashSet<CredentialPath>();

            //§7.1.1's abort clauses: a string component demands objects, a null or integer
            //component demands arrays, of EVERY currently selected element. A selection that
            //mixes shapes is an error, not a filter.
            if(!IsEverySelectedNodeAdmissible(credential, selected, isObjectRequired: segment.IsKey))
            {
                value = null;

                return false;
            }

            foreach(CredentialPath current in selected)
            {
                if(segment.IsKey)
                {
                    CredentialPath candidate = current.Append(segment.KeyValue!);
                    if(IsAvailable(credential, candidate))
                    {
                        next.Add(candidate);
                    }
                }
                else if(segment.IsIndex)
                {
                    CredentialPath candidate = current.Append(segment.IndexValue!.Value);
                    if(IsAvailable(credential, candidate))
                    {
                        next.Add(candidate);
                    }
                }
                else
                {
                    foreach(CredentialPath child in ImmediateArrayChildren(credential, current))
                    {
                        next.Add(child);
                    }
                }
            }

            selected = next;

            if(selected.Count == 0)
            {
                value = null;

                return false;
            }
        }

        var values = new List<object?>();
        foreach(CredentialPath path in selected)
        {
            if(TryGetValue(credential, path, out object? resolved))
            {
                values.Add(resolved);
            }
        }

        if(values.Count == 0)
        {
            value = null;

            return false;
        }

        value = values.Count == 1 ? values[0] : values;

        return true;
    }


    /// <summary>
    /// Whether every currently selected node has the shape the next path component demands, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.1.1">
    /// OpenID for Verifiable Presentations 1.0 §7.1.1</see>: a string component requires objects
    /// ("If any of the currently selected element(s) is not an object, abort processing and return
    /// an error"), a <see langword="null"/> or integer component requires arrays.
    /// </summary>
    /// <remarks>
    /// The credential's root is the payload's own top-level object, which no claim map carries as
    /// a node of its own, so it answers as an object. Every other node answers from the value the
    /// parse materialized: a JSON object or CBOR map is an <see cref="IDictionary"/>, a JSON or
    /// CBOR array is an <see cref="IList"/>, and a scalar is neither.
    /// </remarks>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    /// <param name="credential">The token the paths are resolved against.</param>
    /// <param name="selected">The currently selected paths.</param>
    /// <param name="isObjectRequired">Whether the next component demands objects rather than arrays.</param>
    private static bool IsEverySelectedNodeAdmissible<TEnvelope>(
        SdToken<TEnvelope> credential,
        HashSet<CredentialPath> selected,
        bool isObjectRequired)
        where TEnvelope : notnull
    {
        foreach(CredentialPath path in selected)
        {
            if(path.Equals(CredentialPath.Root))
            {
                if(!isObjectRequired)
                {
                    return false;
                }

                continue;
            }

            if(!TryGetValue(credential, path, out object? node))
            {
                return false;
            }

            bool isAdmissible = isObjectRequired ? node is IDictionary : node is IList;
            if(!isAdmissible)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Every immediate array-index child of a path, across the disclosure paths, the
    /// unconditionally disclosed claims and the disclosure-interior claims — the "all elements of
    /// the currently selected array(s)" a null component selects per §7.1.1.
    /// </summary>
    /// <typeparam name="TEnvelope">The SD-token envelope type.</typeparam>
    /// <param name="credential">The token to enumerate children in.</param>
    /// <param name="parent">The parent path whose array-index children are wanted.</param>
    private static IEnumerable<CredentialPath> ImmediateArrayChildren<TEnvelope>(SdToken<TEnvelope> credential, CredentialPath parent)
        where TEnvelope : notnull
    {
        foreach(CredentialPath candidate in credential.DisclosurePaths.Paths)
        {
            if(IsImmediateArrayChild(candidate, parent))
            {
                yield return candidate;
            }
        }

        foreach(CredentialPath candidate in credential.IssuerSignedClaims.Keys)
        {
            if(IsImmediateArrayChild(candidate, parent))
            {
                yield return candidate;
            }
        }

        foreach(CredentialPath candidate in credential.DisclosureInteriorClaims.Keys)
        {
            if(IsImmediateArrayChild(candidate, parent))
            {
                yield return candidate;
            }
        }
    }


    /// <summary>Whether a path is an array-index child of a parent path.</summary>
    /// <param name="candidate">The path to test.</param>
    /// <param name="parent">The would-be parent path.</param>
    private static bool IsImmediateArrayChild(CredentialPath candidate, CredentialPath parent) =>
        candidate.Parent is CredentialPath candidateParent
        && candidateParent.Equals(parent)
        && candidate.LeafIsArrayIndex;
}
