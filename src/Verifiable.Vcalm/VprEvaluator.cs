using System.Collections.Generic;
using System.Collections.Immutable;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.JsonPointer;

namespace Verifiable.Vcalm;

/// <summary>
/// The holder-side "what can I present for this verifiable presentation request" computation
/// (§3.4): given a parsed <see cref="VerifiablePresentationRequest"/> and a set of held VC-DM 2.0
/// credentials, it reports which §3.4.5 groups the holder can satisfy and the minimal disclosure each
/// match implies. The §3.6 exchange engine (a later surface) calls this when a holder participates in
/// an exchange.
/// </summary>
/// <remarks>
/// <para>
/// The query types compose existing engines rather than re-implementing matching: a
/// <see cref="DigitalCredentialQueryLanguageQuery"/> evaluates through the existing
/// <see cref="DcqlEvaluator"/> (via the VC-DM 2.0 <see cref="VcalmDcqlAdapters"/>); a
/// <see cref="QueryByExampleQuery"/> matches the §3.4.2 example fields against the credential's
/// <c>type</c> / <c>@context</c> / <c>credentialSubject</c> and the <c>acceptedIssuers</c> against the
/// credential's issuer; a <see cref="DidAuthenticationQuery"/> is a holder-DID-plus-cryptosuite
/// predicate (the holder must control an accepted-method DID and be able to sign with an accepted
/// cryptosuite), not a credential match.
/// </para>
/// <para>
/// §3.4.5 fixes the algebra: query entries sharing a <c>group</c> value are ANDed, entries with a
/// different or missing group are ORed. The request is satisfiable when at least one OR-group is fully
/// satisfiable.
/// </para>
/// </remarks>
public static class VprEvaluator
{
    /// <summary>
    /// Evaluates a verifiable presentation request against held credentials using the default VC-DM
    /// 2.0 DCQL adapters.
    /// </summary>
    /// <param name="request">The parsed verifiable presentation request.</param>
    /// <param name="heldCredentials">The credentials the holder holds.</param>
    /// <param name="holderDids">
    /// The holder DIDs available for a §3.4.3 DID Authentication query, or <see langword="null"/> when
    /// the holder offers none.
    /// </param>
    /// <param name="holderCryptosuites">
    /// The Data Integrity cryptosuites the holder can sign a §3.4.3 authentication proof with (e.g.
    /// <c>ecdsa-rdfc-2019</c>), or <see langword="null"/> when the holder advertises none. A DID
    /// Authentication query that constrains <c>acceptedCryptosuites</c> is satisfiable only when the
    /// holder can produce one of the accepted cryptosuites — §3.4.3: "the holder MUST choose [from
    /// acceptedCryptosuites] when generating the authentication proof."
    /// </param>
    /// <returns>The §3.4.5-grouped satisfaction outcome.</returns>
    public static VprEvaluationResult Evaluate(
        VerifiablePresentationRequest request,
        IReadOnlyList<VerifiableCredential> heldCredentials,
        IReadOnlyCollection<string>? holderDids = null,
        IReadOnlyCollection<string>? holderCryptosuites = null) =>
        Evaluate(
            request,
            heldCredentials,
            VcalmDcqlAdapters.MetadataExtractor,
            VcalmDcqlAdapters.ClaimExtractor,
            holderDids,
            holderCryptosuites);


    /// <summary>
    /// Evaluates a verifiable presentation request against held credentials, sourcing the DCQL
    /// metadata / claim extractors from the caller (for a held-credential representation other than the
    /// default VC-DM 2.0 view).
    /// </summary>
    /// <param name="request">The parsed verifiable presentation request.</param>
    /// <param name="heldCredentials">The credentials the holder holds.</param>
    /// <param name="metadataExtractor">The DCQL metadata extractor for the held credentials.</param>
    /// <param name="claimExtractor">The DCQL claim extractor for the held credentials.</param>
    /// <param name="holderDids">
    /// The holder DIDs available for a §3.4.3 DID Authentication query, or <see langword="null"/> when
    /// the holder offers none.
    /// </param>
    /// <param name="holderCryptosuites">
    /// The Data Integrity cryptosuites the holder can sign a §3.4.3 authentication proof with (e.g.
    /// <c>ecdsa-rdfc-2019</c>), or <see langword="null"/> when the holder advertises none. A DID
    /// Authentication query that constrains <c>acceptedCryptosuites</c> is satisfiable only when the
    /// holder can produce one of the accepted cryptosuites — §3.4.3: "the holder MUST choose [from
    /// acceptedCryptosuites] when generating the authentication proof."
    /// </param>
    /// <returns>The §3.4.5-grouped satisfaction outcome.</returns>
    public static VprEvaluationResult Evaluate(
        VerifiablePresentationRequest request,
        IReadOnlyList<VerifiableCredential> heldCredentials,
        DcqlMetadataExtractor<VerifiableCredential> metadataExtractor,
        DcqlClaimExtractor<VerifiableCredential> claimExtractor,
        IReadOnlyCollection<string>? holderDids = null,
        IReadOnlyCollection<string>? holderCryptosuites = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(heldCredentials);
        ArgumentNullException.ThrowIfNull(metadataExtractor);
        ArgumentNullException.ThrowIfNull(claimExtractor);

        //§3.4.5: entries sharing a group value are ANDed; entries with a different or missing group
        //are ORed. An entry with no group is its own standalone OR-alternative — keyed by a per-entry
        //sentinel so it is never merged with another ungrouped entry.
        List<(string? GroupKey, List<VcalmPresentationQuery> Entries)> groups = [];
        Dictionary<string, int> groupIndexByKey = new(StringComparer.Ordinal);

        foreach(VcalmPresentationQuery query in request.Query)
        {
            if(query.Group is null)
            {
                groups.Add((null, [query]));

                continue;
            }

            if(groupIndexByKey.TryGetValue(query.Group, out int existing))
            {
                groups[existing].Entries.Add(query);
            }
            else
            {
                groupIndexByKey[query.Group] = groups.Count;
                groups.Add((query.Group, [query]));
            }
        }

        ImmutableArray<VprGroupResult>.Builder groupResults = ImmutableArray.CreateBuilder<VprGroupResult>();
        bool anyGroupSatisfied = false;

        foreach((string? groupKey, List<VcalmPresentationQuery> entries) in groups)
        {
            ImmutableArray<VprQueryMatch>.Builder queryMatches = ImmutableArray.CreateBuilder<VprQueryMatch>();
            bool allSatisfied = true;

            foreach(VcalmPresentationQuery entry in entries)
            {
                VprQueryMatch match = EvaluateEntry(
                    entry, heldCredentials, metadataExtractor, claimExtractor, holderDids, holderCryptosuites);
                queryMatches.Add(match);
                allSatisfied = allSatisfied && match.IsSatisfied;
            }

            anyGroupSatisfied = anyGroupSatisfied || allSatisfied;
            groupResults.Add(new VprGroupResult
            {
                GroupKey = groupKey,
                IsSatisfied = allSatisfied,
                QueryMatches = queryMatches.ToImmutable()
            });
        }

        return new VprEvaluationResult
        {
            IsSatisfiable = anyGroupSatisfied,
            Groups = groupResults.ToImmutable()
        };
    }


    private static VprQueryMatch EvaluateEntry(
        VcalmPresentationQuery entry,
        IReadOnlyList<VerifiableCredential> heldCredentials,
        DcqlMetadataExtractor<VerifiableCredential> metadataExtractor,
        DcqlClaimExtractor<VerifiableCredential> claimExtractor,
        IReadOnlyCollection<string>? holderDids,
        IReadOnlyCollection<string>? holderCryptosuites) => entry switch
        {
            QueryByExampleQuery qbe => EvaluateQueryByExample(qbe, heldCredentials),
            DigitalCredentialQueryLanguageQuery dcql =>
                EvaluateDcql(dcql, heldCredentials, metadataExtractor, claimExtractor),
            DidAuthenticationQuery didAuth => EvaluateDidAuthentication(didAuth, holderDids, holderCryptosuites),

            //§3.4.4 (editor-unstable) and an open-extension UnknownQuery are not satisfied from held
            //verifiable credentials; they are modeled and reported as unsatisfied, never gated.
            _ => new VprQueryMatch { QueryType = entry.Type, IsSatisfied = false }
        };


    //§3.4.2: a held credential matches when its type / @context cover the example's requested values,
    //every requested credentialSubject field is present (and, when the requested value is non-empty,
    //equal), and the issuer is one of acceptedIssuers (when constrained). Any requested field is a
    //required field — the §3.4.2 selective-disclosure note — so the requested fields ARE the minimal
    //disclosure.
    private static VprQueryMatch EvaluateQueryByExample(
        QueryByExampleQuery query,
        IReadOnlyList<VerifiableCredential> heldCredentials)
    {
        QueryByExampleCredentialQuery credentialQuery = query.CredentialQuery;
        ImmutableArray<VprCredentialMatch>.Builder matches = ImmutableArray.CreateBuilder<VprCredentialMatch>();

        foreach(VerifiableCredential credential in heldCredentials)
        {
            if(!MatchesExample(credential, credentialQuery.Example))
            {
                continue;
            }

            if(!MatchesAcceptedIssuers(credential, credentialQuery.AcceptedIssuers))
            {
                continue;
            }

            matches.Add(new VprCredentialMatch
            {
                Credential = credential,
                Disclosures = RequestedDisclosurePaths(credentialQuery.Example)
            });
        }

        return new VprQueryMatch
        {
            QueryType = query.Type,
            IsSatisfied = matches.Count > 0,
            Matches = matches.ToImmutable()
        };
    }


    private static bool MatchesExample(VerifiableCredential credential, QueryByExampleCredential? example)
    {
        if(example is null)
        {
            //A credentialQuery with no example places no claim/type constraint — any held credential
            //is a candidate (the issuer / cryptosuite / envelope constraints still apply).
            return true;
        }

        //§3.4.2 example.type: every requested type token MUST be among the credential's types.
        if(!example.Types.IsEmpty)
        {
            HashSet<string> credentialTypes = credential.Type is { Count: > 0 }
                ? new HashSet<string>(credential.Type, StringComparer.Ordinal)
                : [];
            foreach(string requestedType in example.Types)
            {
                if(!credentialTypes.Contains(requestedType))
                {
                    return false;
                }
            }
        }

        //§3.4.2 example.@context: every requested context MUST be among the credential's contexts.
        if(!example.Context.IsEmpty)
        {
            HashSet<string> contexts = CollectContexts(credential);
            foreach(string requestedContext in example.Context)
            {
                if(!contexts.Contains(requestedContext))
                {
                    return false;
                }
            }
        }

        //§3.4.2 example.credentialSubject: every requested field MUST be present; a non-empty
        //requested value additionally constrains the disclosed value, an empty-string value matches
        //any value.
        foreach(KeyValuePair<string, string> field in example.SubjectFields)
        {
            if(!TryReadSubjectField(credential, field.Key, out object? actual))
            {
                return false;
            }

            if(field.Value.Length == 0)
            {
                //§3.4.2: empty string means "field requested, any value".
                continue;
            }

            if(!ValueEquals(actual, field.Value))
            {
                return false;
            }
        }

        return true;
    }


    //§3.4.2 acceptedIssuers: when present, the credential's issuer MUST be one of the directly named
    //issuers. A recognizedIn reference points to a VerifiableRecognitionCredential the holder cannot
    //resolve here, so a query that constrains issuers SOLELY by recognizedIn is treated as accepting
    //any issuer (the recognition resolution is a verifier/holder-flow concern, not this computation).
    private static bool MatchesAcceptedIssuers(
        VerifiableCredential credential,
        ImmutableArray<QueryByExampleAcceptedIssuer> acceptedIssuers)
    {
        if(acceptedIssuers.IsEmpty)
        {
            return true;
        }

        bool hasDirectConstraint = false;
        string? issuerId = credential.Issuer?.Id;
        foreach(QueryByExampleAcceptedIssuer accepted in acceptedIssuers)
        {
            if(accepted.Id is null)
            {
                continue;
            }

            hasDirectConstraint = true;
            if(string.Equals(accepted.Id, issuerId, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return !hasDirectConstraint;
    }


    //§3.4.2 selective-disclosure: any field included is required. The minimal disclosure for a QBE
    //match is the requested credentialSubject field paths (a type-only example discloses nothing
    //claim-specific).
    private static ImmutableArray<CredentialPath> RequestedDisclosurePaths(QueryByExampleCredential? example)
    {
        if(example is null || example.SubjectFields.IsEmpty)
        {
            return ImmutableArray<CredentialPath>.Empty;
        }

        ImmutableArray<CredentialPath>.Builder paths = ImmutableArray.CreateBuilder<CredentialPath>();
        foreach(KeyValuePair<string, string> field in example.SubjectFields)
        {
            JsonPointer.JsonPointer pointer = JsonPointer.JsonPointer.Root
                .Append(VcalmParameterNames.CredentialSubject)
                .Append(field.Key);
            paths.Add(new CredentialPath(pointer));
        }

        return paths.ToImmutable();
    }


    //§3.4 DCQL co-equal type: evaluate through the existing DcqlEvaluator. A match's minimal
    //disclosure is the matched claim patterns resolved to concrete credentialSubject paths.
    private static VprQueryMatch EvaluateDcql(
        DigitalCredentialQueryLanguageQuery query,
        IReadOnlyList<VerifiableCredential> heldCredentials,
        DcqlMetadataExtractor<VerifiableCredential> metadataExtractor,
        DcqlClaimExtractor<VerifiableCredential> claimExtractor)
    {
        PreparedDcqlQuery prepared = DcqlPreparer.Prepare(query.Query);
        ImmutableArray<VprCredentialMatch>.Builder matches = ImmutableArray.CreateBuilder<VprCredentialMatch>();

        foreach(DcqlMatch<VerifiableCredential> dcqlMatch in DcqlEvaluator.Evaluate(
            prepared, heldCredentials, metadataExtractor, claimExtractor))
        {
            matches.Add(new VprCredentialMatch
            {
                Credential = dcqlMatch.Credential,
                Disclosures = ResolvePatterns(dcqlMatch.RequiredDisclosurePatterns)
            });
        }

        return new VprQueryMatch
        {
            QueryType = query.Type,
            IsSatisfied = matches.Count > 0,
            Matches = matches.ToImmutable()
        };
    }


    private static ImmutableArray<CredentialPath> ResolvePatterns(IReadOnlySet<DcqlClaimPattern> patterns)
    {
        ImmutableArray<CredentialPath>.Builder paths = ImmutableArray.CreateBuilder<CredentialPath>();
        foreach(DcqlClaimPattern pattern in patterns)
        {
            if(pattern.TryResolve(out CredentialPath path))
            {
                paths.Add(path);
            }
        }

        return paths.ToImmutable();
    }


    //§3.4.3: the holder satisfies the request when it controls a DID of an accepted method AND — when
    //the query constrains acceptedCryptosuites — can sign the authentication proof with one of those
    //cryptosuites ("the holder MUST choose [from acceptedCryptosuites] when generating the
    //authentication proof"). The predicate is on the holder's DIDs and signing capability, not on held
    //verifiable credentials. A constrained acceptedCryptosuites with no demonstrable holder cryptosuite
    //fails closed: the holder cannot produce an acceptable proof, so the query is not satisfied.
    private static VprQueryMatch EvaluateDidAuthentication(
        DidAuthenticationQuery query,
        IReadOnlyCollection<string>? holderDids,
        IReadOnlyCollection<string>? holderCryptosuites)
    {
        bool hasAcceptedDid = false;
        if(holderDids is not null)
        {
            foreach(string holderDid in holderDids)
            {
                if(query.IsHolderAccepted(holderDid))
                {
                    hasAcceptedDid = true;

                    break;
                }
            }
        }

        bool isSatisfied = hasAcceptedDid && HolderCanProduceAcceptedCryptosuite(query, holderCryptosuites);

        return new VprQueryMatch
        {
            QueryType = query.Type,
            IsSatisfied = isSatisfied
        };
    }


    //§3.4.3 acceptedCryptosuites: an empty array places no cryptosuite constraint (any suite is
    //acceptable). When constrained, the holder must advertise at least one cryptosuite that is in the
    //accepted set; a holder that advertises none (null/empty) cannot demonstrate an acceptable proof,
    //so a constrained query fails closed.
    private static bool HolderCanProduceAcceptedCryptosuite(
        DidAuthenticationQuery query,
        IReadOnlyCollection<string>? holderCryptosuites)
    {
        if(query.AcceptedCryptosuites.IsEmpty)
        {
            return true;
        }

        if(holderCryptosuites is null || holderCryptosuites.Count == 0)
        {
            return false;
        }

        HashSet<string> accepted = new(query.AcceptedCryptosuites, StringComparer.Ordinal);

        foreach(string holderCryptosuite in holderCryptosuites)
        {
            if(accepted.Contains(holderCryptosuite))
            {
                return true;
            }
        }

        return false;
    }


    private static HashSet<string> CollectContexts(VerifiableCredential credential)
    {
        HashSet<string> contexts = new(StringComparer.Ordinal);
        if(credential.Context?.Contexts is null)
        {
            return contexts;
        }

        foreach(object context in credential.Context.Contexts)
        {
            if(context is string text)
            {
                contexts.Add(text);
            }
        }

        return contexts;
    }


    private static bool TryReadSubjectField(VerifiableCredential credential, string fieldName, out object? value)
    {
        value = null;
        if(credential.CredentialSubject is null)
        {
            return false;
        }

        foreach(CredentialSubject subject in credential.CredentialSubject)
        {
            if(subject.AdditionalData is not null
                && subject.AdditionalData.TryGetValue(fieldName, out value))
            {
                return true;
            }
        }

        return false;
    }


    private static bool ValueEquals(object? actual, string requested)
    {
        if(actual is string text)
        {
            return string.Equals(text, requested, StringComparison.Ordinal);
        }

        return string.Equals(actual?.ToString(), requested, StringComparison.Ordinal);
    }
}
