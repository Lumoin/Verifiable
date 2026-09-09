using System.Collections.Frozen;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Core.Dcql;

/// <summary>
/// Delegate for extracting claim values from credentials.
/// </summary>
/// <typeparam name="TCredential">The credential type.</typeparam>
/// <param name="credential">The credential to extract from.</param>
/// <param name="pattern">The claim path pattern to extract.</param>
/// <param name="value">The extracted value, if found.</param>
/// <returns><see langword="true"/> if the claim exists at the path; otherwise, <see langword="false"/>.</returns>
/// <remarks>
/// <para>
/// Implementations are format-specific. For SD-JWT, this navigates JSON structure
/// and handles disclosed claims. For mdoc, this accesses namespace/element pairs.
/// </para>
/// <para>
/// The value returned should be the native representation (string, number, boolean, etc.)
/// for comparison with <see cref="ClaimsQuery.Values"/> constraints.
/// </para>
/// </remarks>
public delegate bool DcqlClaimExtractor<TCredential>(
    TCredential credential,
    DcqlClaimPattern pattern,
    out object? value);

/// <summary>
/// Delegate for extracting credential metadata for coarse matching.
/// </summary>
/// <typeparam name="TCredential">The credential type.</typeparam>
/// <param name="credential">The credential to extract metadata from.</param>
/// <returns>The credential metadata.</returns>
public delegate DcqlCredentialMetadata DcqlMetadataExtractor<TCredential>(TCredential credential);

/// <summary>
/// Metadata about a credential for DCQL matching.
/// </summary>
[DebuggerDisplay("Format={Format} Type={CredentialType} TrustedAuthorityEvidence={TrustedAuthorityEvidence}")]
public record DcqlCredentialMetadata
{
    /// <summary>The shared empty <see cref="AdditionalTypes"/> default value.</summary>
    private static IReadOnlySet<string> EmptyAdditionalTypes { get; } = FrozenSet<string>.Empty;

    /// <summary>
    /// The credential format (e.g., "dc+sd-jwt", "mso_mdoc").
    /// </summary>
    public required string Format { get; init; }

    /// <summary>
    /// The credential type (vct for SD-JWT, doctype for mdoc).
    /// </summary>
    public string? CredentialType { get; init; }

    /// <summary>
    /// Additional type identifiers the credential itself declares it is also known by or
    /// inherits from — the SD-JWT VC <c>aka_vcts</c> claim
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.2">
    /// SD-JWT VC §2.2.2.2</see>). OpenID for Verifiable Presentations 1.0 Appendix B.3.5's
    /// <c>vct_values</c> MAY-level inheritance rule is answered against this set as far as the
    /// credential's own claims carry it; Type Metadata <c>extends</c> resolution (SD-JWT VC §5)
    /// needs a metadata fetch this evaluator does not perform.
    /// </summary>
    public IReadOnlySet<string> AdditionalTypes { get; init; } = EmptyAdditionalTypes;

    /// <summary>
    /// The credential's OID4VP 1.0 §6.1.1 trust evidence — the facts a <c>trusted_authorities</c>
    /// entry is matched against (<see cref="TrustedAuthoritiesQuery.Matches(TrustedAuthorityEvidence)"/>).
    /// <see langword="null"/> when the format or wiring surfaces none, in which case a
    /// <c>trusted_authorities</c> constraint on this credential fails closed
    /// (<see cref="DcqlFailureReasons.TrustedAuthorityEvidenceAbsent"/>).
    /// </summary>
    public TrustedAuthorityEvidence? TrustedAuthorityEvidence { get; init; }

    /// <summary>
    /// All claim paths present in the credential as concrete <see cref="CredentialPath"/> values.
    /// </summary>
    /// <remarks>
    /// For selective disclosure credentials, this includes all paths
    /// that could potentially be disclosed, not just currently disclosed ones.
    /// </remarks>
    public IReadOnlySet<CredentialPath>? AvailablePaths { get; init; }
}

/// <summary>
/// Result of evaluating a credential against a DCQL credential query.
/// </summary>
/// <remarks>
/// <para>
/// The match carries both the DCQL claim patterns that matched and the resolved
/// concrete <see cref="CredentialPath"/> values for the disclosure computation.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The credential type.</typeparam>
[DebuggerDisplay("CredentialQueryId={CredentialQueryId} MatchedPatterns={MatchedPatterns.Count}")]
public record DcqlMatch<TCredential>
{
    /// <summary>
    /// The credential that matched.
    /// </summary>
    public required TCredential Credential { get; init; }

    /// <summary>
    /// The ID of the credential query that was matched.
    /// </summary>
    public required CredentialQueryId CredentialQueryId { get; init; }

    /// <summary>
    /// The DCQL claim patterns that were successfully matched.
    /// </summary>
    public required IReadOnlySet<DcqlClaimPattern> MatchedPatterns { get; init; }

    /// <summary>
    /// The DCQL claim patterns that are required for disclosure.
    /// </summary>
    public required IReadOnlySet<DcqlClaimPattern> RequiredDisclosurePatterns { get; init; }
}

/// <summary>
/// Result of evaluating a credential against a single credential query.
/// </summary>
[DebuggerDisplay("Matches={Matches} CredentialQueryId={CredentialQueryId} FailureReason={FailureReason}")]
public record DcqlEvaluationResult
{
    /// <summary>
    /// Whether the credential matches the query requirements.
    /// </summary>
    public required bool Matches { get; init; }

    /// <summary>
    /// The credential query ID.
    /// </summary>
    public required CredentialQueryId CredentialQueryId { get; init; }

    /// <summary>
    /// Claim patterns that were found and matched.
    /// </summary>
    public IReadOnlySet<DcqlClaimPattern>? MatchedPatterns { get; init; }

    /// <summary>
    /// Required claim patterns that were missing from the credential.
    /// </summary>
    public IReadOnlyList<DcqlClaimPattern>? MissingRequiredPatterns { get; init; }

    /// <summary>
    /// Claim patterns where value constraints failed.
    /// </summary>
    public IReadOnlyList<DcqlClaimPattern>? FailedValueConstraints { get; init; }

    /// <summary>
    /// Reason for non-match, if applicable.
    /// </summary>
    public string? FailureReason { get; init; }
}

/// <summary>
/// Evaluates credentials against DCQL queries.
/// </summary>
public static class DcqlEvaluator
{
    /// <summary>
    /// Evaluates credentials against a prepared DCQL query.
    /// </summary>
    /// <typeparam name="TCredential">The credential type.</typeparam>
    /// <param name="preparedQuery">The prepared DCQL query.</param>
    /// <param name="credentials">The credentials to evaluate.</param>
    /// <param name="metadataExtractor">Extracts credential metadata for coarse matching.</param>
    /// <param name="claimExtractor">Extracts claim values for fine matching.</param>
    /// <returns>Matches for credentials that satisfy credential queries.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="preparedQuery"/> is not <see cref="PreparedDcqlQuery.IsValid"/> — evaluating a
    /// query that failed preparation is a caller defect, not a wire answer (the wire refusal belongs
    /// where the request is read); the exception message names the query's first recorded
    /// <see cref="PreparedDcqlQuery.ValidationIssues"/>. Per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OID4VP 1.0 §6.1</see> an identifier that is not "a non-empty string consisting of alphanumeric,
    /// underscore (_), or hyphen (-) characters" never evaluates.
    /// </exception>
    /// <remarks>
    /// The argument checks and the invalid-query refusal run when this method is CALLED, not when the
    /// returned sequence is first enumerated: the deferred work lives in a private iterator this
    /// method returns, so a caller that hands over a bad query learns it at the call site rather than
    /// at some later <c>foreach</c> whose stack no longer names the mistake.
    /// </remarks>
    public static IEnumerable<DcqlMatch<TCredential>> Evaluate<TCredential>(
        PreparedDcqlQuery preparedQuery,
        IEnumerable<TCredential> credentials,
        DcqlMetadataExtractor<TCredential> metadataExtractor,
        DcqlClaimExtractor<TCredential> claimExtractor)
    {
        ArgumentNullException.ThrowIfNull(preparedQuery);
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(metadataExtractor);
        ArgumentNullException.ThrowIfNull(claimExtractor);

        if(!preparedQuery.IsValid)
        {
            throw new ArgumentException(preparedQuery.ValidationIssues[0], nameof(preparedQuery));
        }

        return EvaluateChecked(preparedQuery, credentials, metadataExtractor, claimExtractor);
    }


    /// <summary>
    /// Walks the credentials against a prepared query whose arguments
    /// <see cref="Evaluate{TCredential}(PreparedDcqlQuery, IEnumerable{TCredential}, DcqlMetadataExtractor{TCredential}, DcqlClaimExtractor{TCredential})"/>
    /// already checked, yielding one match per credential and credential query that satisfy each
    /// other.
    /// </summary>
    /// <typeparam name="TCredential">The credential type.</typeparam>
    /// <param name="preparedQuery">The prepared, valid DCQL query.</param>
    /// <param name="credentials">The credentials to evaluate.</param>
    /// <param name="metadataExtractor">Extracts credential metadata for coarse matching.</param>
    /// <param name="claimExtractor">Extracts claim values for fine matching.</param>
    /// <returns>Matches for credentials that satisfy credential queries.</returns>
    private static IEnumerable<DcqlMatch<TCredential>> EvaluateChecked<TCredential>(
        PreparedDcqlQuery preparedQuery,
        IEnumerable<TCredential> credentials,
        DcqlMetadataExtractor<TCredential> metadataExtractor,
        DcqlClaimExtractor<TCredential> claimExtractor)
    {
        if(preparedQuery.Query.Credentials is null)
        {
            yield break;
        }

        foreach(var credential in credentials)
        {
            var metadata = metadataExtractor(credential);

            foreach(var credentialQuery in preparedQuery.Query.Credentials)
            {
                var result = EvaluateSingle(credentialQuery, credential, metadata, claimExtractor);

                if(result.Matches)
                {
                    yield return new DcqlMatch<TCredential>
                    {
                        Credential = credential,
                        CredentialQueryId = result.CredentialQueryId,
                        MatchedPatterns = result.MatchedPatterns ?? new HashSet<DcqlClaimPattern>(),
                        RequiredDisclosurePatterns = CollectRequiredPatterns(credentialQuery)
                    };
                }
            }
        }
    }

    /// <summary>
    /// Evaluates a single credential against a single credential query.
    /// </summary>
    /// <typeparam name="TCredential">The credential type.</typeparam>
    /// <param name="credentialQuery">The credential query.</param>
    /// <param name="credential">The credential to evaluate.</param>
    /// <param name="metadata">The credential metadata.</param>
    /// <param name="claimExtractor">Extracts claim values for matching.</param>
    /// <returns>The evaluation result.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="credentialQuery"/>'s <c>Id</c> fails
    /// <see cref="Dcql.CredentialQueryId.TryCreate(string?, out CredentialQueryId?)"/> — an
    /// identifier that leaves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OID4VP 1.0 §6.1</see> never evaluates.
    /// </exception>
    public static DcqlEvaluationResult EvaluateSingle<TCredential>(
        CredentialQuery credentialQuery,
        TCredential credential,
        DcqlCredentialMetadata metadata,
        DcqlClaimExtractor<TCredential> claimExtractor)
    {
        ArgumentNullException.ThrowIfNull(credentialQuery);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(claimExtractor);

        if(!CredentialQueryId.TryCreate(credentialQuery.Id, out CredentialQueryId? credentialQueryId))
        {
            throw new ArgumentException(
                $"Credential query ID '{credentialQuery.Id}' is not a valid OID4VP 1.0 §6.1 identifier.",
                nameof(credentialQuery));
        }

        //Check format match.
        if(!string.Equals(credentialQuery.Format, metadata.Format, StringComparison.Ordinal))
        {
            return new DcqlEvaluationResult
            {
                Matches = false,
                CredentialQueryId = credentialQueryId,
                FailureReason = DcqlFailureReasons.FormatMismatch(credentialQuery.Format, metadata.Format)
            };
        }

        //Appendix B.3.5 makes meta.vct_values REQUIRED for dc+sd-jwt: "vct_values: REQUIRED. A
        //non-empty array of strings that specifies allowed values for the type of the requested
        //Verifiable Credential." A query that omits it expresses no type constraint where the
        //format demands one, so no credential can be shown to satisfy it (§6.4.2's MUST NOT).
        //The rule is enforced here, on the path a wallet or verifier actually evaluates, rather
        //than only where a caller may or may not have run the preparer first.
        if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdJwt, StringComparison.Ordinal)
            && credentialQuery.Meta?.VctValues is not { Count: > 0 })
        {
            return new DcqlEvaluationResult
            {
                Matches = false,
                CredentialQueryId = credentialQueryId,
                FailureReason = DcqlFailureReasons.SdJwtVctValuesRequired
            };
        }

        //Check type constraint. OpenID for Verifiable Presentations 1.0 §6.4.2: "Credentials not
        //matching the respective constraints expressed within credentials MUST NOT be returned" —
        //a credential whose type cannot be shown to satisfy the constraint is not a match,
        //whether because its type is unknown or because it declares a different one.
        if(credentialQuery.Meta?.HasTypeConstraints == true && credentialQuery.Format is not null)
        {
            IReadOnlyList<string>? typeConstraints = credentialQuery.Meta.GetTypeConstraints(credentialQuery.Format);

            //A meta that constrains the type but names no value the query's own format reads —
            //a doctype_value under an SD-JWT format, say — leaves the constraint unanswerable.
            //§6.4.2 decides it the same way: unanswerable is not a match.
            if(typeConstraints is not { Count: > 0 })
            {
                return new DcqlEvaluationResult
                {
                    Matches = false,
                    CredentialQueryId = credentialQueryId,
                    FailureReason = DcqlFailureReasons.TypeConstraintUnreadable(credentialQuery.Format)
                };
            }

            if(metadata.CredentialType is null)
            {
                return new DcqlEvaluationResult
                {
                    Matches = false,
                    CredentialQueryId = credentialQueryId,
                    FailureReason = DcqlFailureReasons.CredentialTypeUnknown
                };
            }

            bool typeMatches = false;
            foreach(string constraint in typeConstraints)
            {
                //B.3.5: "The Wallet MAY return Credentials that inherit from any of the
                //specified types" — answered against the credential's own aka_vcts claim.
                if(string.Equals(constraint, metadata.CredentialType, StringComparison.Ordinal)
                    || metadata.AdditionalTypes.Contains(constraint))
                {
                    typeMatches = true;
                    break;
                }
            }

            if(!typeMatches)
            {
                return new DcqlEvaluationResult
                {
                    Matches = false,
                    CredentialQueryId = credentialQueryId,
                    FailureReason = DcqlFailureReasons.CredentialTypeNotAccepted(metadata.CredentialType)
                };
            }
        }

        //Check trusted authorities. §6.1's SHOULD is a Wallet-side minimization aid, but §6.4.2's
        //MUST NOT still governs: a credential with no trust evidence at all cannot be shown to
        //satisfy a trusted_authorities constraint, so it does not match.
        if(credentialQuery.TrustedAuthorities is { Count: > 0 })
        {
            if(metadata.TrustedAuthorityEvidence is not { } evidence)
            {
                return new DcqlEvaluationResult
                {
                    Matches = false,
                    CredentialQueryId = credentialQueryId,
                    FailureReason = DcqlFailureReasons.TrustedAuthorityEvidenceAbsent
                };
            }

            bool anyEntryMatched = false;
            bool everyEntryUnsupported = true;
            foreach(var authority in credentialQuery.TrustedAuthorities)
            {
                if(DcqlTrustedAuthorityTypes.IsAki(authority.Type)
                    || DcqlTrustedAuthorityTypes.IsEtsiTrustedList(authority.Type)
                    || DcqlTrustedAuthorityTypes.IsOpenIdFederation(authority.Type))
                {
                    everyEntryUnsupported = false;
                }

                if(authority.Matches(evidence))
                {
                    anyEntryMatched = true;
                    break;
                }
            }

            if(!anyEntryMatched)
            {
                return new DcqlEvaluationResult
                {
                    Matches = false,
                    CredentialQueryId = credentialQueryId,
                    FailureReason = everyEntryUnsupported
                        ? DcqlFailureReasons.TrustedAuthorityTypeUnsupported(UnsupportedTypesOf(credentialQuery.TrustedAuthorities))
                        : DcqlFailureReasons.TrustedAuthorityUnmatched
                };
            }
        }

        //Check claims.
        if(credentialQuery.Claims is null or { Count: 0 })
        {
            //No claim requirements, format/type match is sufficient.
            return new DcqlEvaluationResult
            {
                Matches = true,
                CredentialQueryId = credentialQueryId,
                MatchedPatterns = new HashSet<DcqlClaimPattern>()
            };
        }

        var matchedPatterns = new HashSet<DcqlClaimPattern>();
        var missingRequired = new List<DcqlClaimPattern>();
        var failedValueConstraints = new List<DcqlClaimPattern>();

        //When claim_sets is present, individual Required flags are ignored.
        bool hasClaimSets = credentialQuery.ClaimSets is { Count: > 0 };

        foreach(var claimQuery in credentialQuery.Claims)
        {
            if(claimQuery.Path is null)
            {
                continue;
            }

            bool claimExists = claimExtractor(credential, claimQuery.Path, out var value);

            if(!claimExists)
            {
                if(claimQuery.Required && !hasClaimSets)
                {
                    missingRequired.Add(claimQuery.Path);
                }

                continue;
            }

            //Check value constraint if specified.
            if(claimQuery.Values is { Count: > 0 })
            {
                bool valueMatches = false;
                foreach(var acceptableValue in claimQuery.Values)
                {
                    if(ValuesMatch(value, acceptableValue))
                    {
                        valueMatches = true;
                        break;
                    }
                }

                if(!valueMatches)
                {
                    if(claimQuery.Required && !hasClaimSets)
                    {
                        failedValueConstraints.Add(claimQuery.Path);
                    }

                    continue;
                }
            }

            matchedPatterns.Add(claimQuery.Path);
        }

        if(missingRequired.Count > 0 || failedValueConstraints.Count > 0)
        {
            return new DcqlEvaluationResult
            {
                Matches = false,
                CredentialQueryId = credentialQueryId,
                MatchedPatterns = matchedPatterns,
                MissingRequiredPatterns = missingRequired.Count > 0 ? missingRequired : null,
                FailedValueConstraints = failedValueConstraints.Count > 0 ? failedValueConstraints : null,
                FailureReason = missingRequired.Count > 0
                    ? DcqlFailureReasons.MissingRequiredClaims(missingRequired)
                    : DcqlFailureReasons.ValueConstraintsFailed(failedValueConstraints)
            };
        }

        //Check claim sets if specified.
        if(hasClaimSets)
        {
            var availableClaimIds = new HashSet<string>();
            foreach(var claimQuery in credentialQuery.Claims)
            {
                if(claimQuery.Path is not null && matchedPatterns.Contains(claimQuery.Path))
                {
                    availableClaimIds.Add(claimQuery.EffectiveId);
                }
            }

            foreach(var claimSet in credentialQuery.ClaimSets!)
            {
                if(claimSet.Required && !claimSet.IsSatisfiedBy(availableClaimIds))
                {
                    return new DcqlEvaluationResult
                    {
                        Matches = false,
                        CredentialQueryId = credentialQueryId,
                        MatchedPatterns = matchedPatterns,
                        FailureReason = DcqlFailureReasons.RequiredClaimSetNotSatisfied
                    };
                }
            }
        }

        return new DcqlEvaluationResult
        {
            Matches = true,
            CredentialQueryId = credentialQueryId,
            MatchedPatterns = matchedPatterns
        };
    }


    /// <summary>Joins the distinct <see cref="TrustedAuthoritiesQuery.Type"/> values of a query's trusted-authorities entries, for naming an unsupported-type failure reason.</summary>
    /// <param name="authorities">The credential query's trusted-authorities entries.</param>
    /// <returns>A comma-separated list of the entries' <c>type</c> values.</returns>
    private static string UnsupportedTypesOf(IReadOnlyList<TrustedAuthoritiesQuery> authorities)
    {
        var types = new HashSet<string>(StringComparer.Ordinal);
        foreach(TrustedAuthoritiesQuery authority in authorities)
        {
            types.Add(authority.Type);
        }

        return string.Join(", ", types);
    }


    private static HashSet<DcqlClaimPattern> CollectRequiredPatterns(CredentialQuery credentialQuery)
    {
        var result = new HashSet<DcqlClaimPattern>();
        foreach(var pattern in credentialQuery.RequiredPatterns())
        {
            result.Add(pattern);
        }

        return result;
    }


    private static bool ValuesMatch(object? actual, object? expected)
    {
        if(actual is null && expected is null)
        {
            return true;
        }

        if(actual is null || expected is null)
        {
            return false;
        }

        //String comparison.
        if(actual is string actualStr && expected is string expectedStr)
        {
            return string.Equals(actualStr, expectedStr, StringComparison.Ordinal);
        }

        //Numeric comparison (handle different numeric types). Neither value is genuinely
        //computed here — both are parsed literals (the claim's wire value and the query's
        //declared value) — so an exact comparison is correct; it is carried as decimal rather
        //than double so a 64-bit integral value compares exactly instead of losing precision
        //to double's 53-bit mantissa. A float or double operand still compares as double: it
        //cannot losslessly convert to decimal (NaN, infinity, or a magnitude decimal cannot
        //represent), and there is no case here where a genuine float is being matched against
        //an out-of-decimal-range value, so double equality is exact for it too.
        if(IsNumeric(actual) && IsNumeric(expected))
        {
            if(actual is float or double || expected is float or double)
            {
                return Convert.ToDouble(actual, CultureInfo.InvariantCulture)
                    == Convert.ToDouble(expected, CultureInfo.InvariantCulture);
            }

            return Convert.ToDecimal(actual, CultureInfo.InvariantCulture)
                == Convert.ToDecimal(expected, CultureInfo.InvariantCulture);
        }

        //Boolean comparison.
        if(actual is bool actualBool && expected is bool expectedBool)
        {
            return actualBool == expectedBool;
        }

        //Fall back to Equals.
        return actual.Equals(expected);
    }

    private static bool IsNumeric(object value)
    {
        return value is byte or sbyte or short or ushort or int or uint
            or long or ulong or float or double or decimal;
    }
}
