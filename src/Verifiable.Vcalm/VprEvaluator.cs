using System.Collections.Immutable;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using JsonPointerType = Lumoin.Veritas.JsonPointer.JsonPointer;

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
/// <c>type</c> / <c>@context</c> / <c>credentialSubject</c>, the <c>acceptedIssuers</c> against the
/// credential's issuer, and the <c>acceptedCryptosuites</c> / <c>acceptedEnvelopes</c> against the way
/// the credential is secured; a <see cref="DidAuthenticationQuery"/> is a holder-DID-plus-cryptosuite
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
    /// holder can produce one of the accepted cryptosuites: acceptedCryptosuites conveys "the cryptography
    /// suites among which the holder MUST choose when generating a cryptographic proof to be submitted to
    /// this verifier" (<see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>).
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
    /// holder can produce one of the accepted cryptosuites: acceptedCryptosuites conveys "the cryptography
    /// suites among which the holder MUST choose when generating a cryptographic proof to be submitted to
    /// this verifier" (<see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>).
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


    /// <summary>
    /// Evaluates one query entry by its type: a Query By Example against the held credentials, a DCQL
    /// query through the <see cref="DcqlEvaluator"/>, a DID Authentication query against the holder's
    /// DIDs and cryptosuites; any other type is reported unsatisfied.
    /// </summary>
    /// <param name="entry">The query entry.</param>
    /// <param name="heldCredentials">The credentials the holder holds.</param>
    /// <param name="metadataExtractor">The DCQL metadata extractor for the held credentials.</param>
    /// <param name="claimExtractor">The DCQL claim extractor for the held credentials.</param>
    /// <param name="holderDids">The holder's DIDs, or <see langword="null"/> when it offers none.</param>
    /// <param name="holderCryptosuites">The holder's cryptosuites, or <see langword="null"/> when it advertises none.</param>
    /// <returns>The entry's match.</returns>
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


    /// <summary>
    /// Evaluates a Query By Example
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>): a held
    /// credential matches when its type / @context cover the example's requested values, every
    /// requested credentialSubject field is present (and, when the requested value is non-empty,
    /// equal), its issuer is one of acceptedIssuers (when constrained), and it is secured the way the
    /// verifier "will accept" (<see cref="IsSecuredAsAccepted"/>, when acceptedCryptosuites or
    /// acceptedEnvelopes constrain it). "Any field included in a Query By Example is a required field",
    /// so the requested fields ARE the minimal disclosure.
    /// </summary>
    /// <remarks>
    /// The accepted issuers and cryptosuites are gathered into ordinal sets once per query, so each held
    /// credential costs one lookup however many issuers or recognized issuers the query names.
    /// </remarks>
    /// <param name="query">The Query By Example entry.</param>
    /// <param name="heldCredentials">The credentials the holder holds.</param>
    /// <returns>The entry's match with every matching credential.</returns>
    private static VprQueryMatch EvaluateQueryByExample(
        QueryByExampleQuery query,
        IReadOnlyList<VerifiableCredential> heldCredentials)
    {
        QueryByExampleCredentialQuery credentialQuery = query.CredentialQuery;
        ImmutableArray<VprCredentialMatch>.Builder matches = ImmutableArray.CreateBuilder<VprCredentialMatch>();
        HashSet<string>? acceptedIssuerIds = CollectAcceptedIssuerIds(credentialQuery.AcceptedIssuers);
        bool isSecuringConstrained = !credentialQuery.AcceptedCryptosuites.IsDefaultOrEmpty
            || !credentialQuery.AcceptedEnvelopes.IsDefaultOrEmpty;
        HashSet<string>? acceptedCryptosuites = credentialQuery.AcceptedCryptosuites.IsDefaultOrEmpty
            ? null
            : new HashSet<string>(credentialQuery.AcceptedCryptosuites, StringComparer.Ordinal);

        foreach(VerifiableCredential credential in heldCredentials)
        {
            if(!MatchesExample(credential, credentialQuery.Example))
            {
                continue;
            }

            if(!MatchesAcceptedIssuers(credential, acceptedIssuerIds))
            {
                continue;
            }

            if(isSecuringConstrained && !IsSecuredAsAccepted(credential, acceptedCryptosuites))
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


    /// <summary>
    /// Whether <paramref name="credential"/> covers the §3.4.2 example: every requested type and
    /// context present, every requested subject field present and, when its requested value is
    /// non-empty, equal.
    /// </summary>
    /// <param name="credential">The held credential.</param>
    /// <param name="example">The example, or <see langword="null"/> when the query carries none.</param>
    /// <returns><see langword="true"/> when the credential covers the example.</returns>
    private static bool MatchesExample(VerifiableCredential credential, QueryByExampleCredential? example)
    {
        if(example is null)
        {
            //A credentialQuery with no example places no claim/type constraint — any held credential
            //is a candidate, and the issuer, cryptosuite and envelope constraints still apply to it.
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


    /// <summary>
    /// Whether <paramref name="credential"/>'s issuer is one of the §3.4.2 <c>acceptedIssuers</c>, the
    /// "entities that the verifier recognizes and accepts as issuers of the verifiable credential"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>).
    /// </summary>
    /// <remarks>
    /// No accepted-issuer set (<see langword="null"/>, an empty list) places no issuer constraint.
    /// Otherwise the credential matches when its issuer id is in the set
    /// <see cref="CollectAcceptedIssuerIds"/> gathered from ANY item, compared exactly; a credential
    /// without an issuer id matches none.
    /// </remarks>
    /// <param name="credential">The held credential.</param>
    /// <param name="acceptedIssuerIds">The issuer ids the query's items accept, or <see langword="null"/> when unconstrained.</param>
    /// <returns><see langword="true"/> when the issuer is accepted.</returns>
    private static bool MatchesAcceptedIssuers(VerifiableCredential credential, HashSet<string>? acceptedIssuerIds) =>
        acceptedIssuerIds is null
        || (credential.Issuer?.Id is { } issuerId && acceptedIssuerIds.Contains(issuerId));


    /// <summary>
    /// Gathers the issuer ids the §3.4.2 accepted-issuer items name into one ordinal set: a direct item
    /// (a URL string or an object's <c>id</c>) names its own id; a <c>recognizedIn</c> item names a
    /// Recognized Entities list, not an issuer, so it contributes only the issuers the caller took from
    /// that list once retrieved and verified (<see cref="QueryByExampleAcceptedIssuer.RecognizedIssuerIds"/>).
    /// A constraint made only of such items accepts no issuer until the caller supplies them, failing
    /// closed rather than treating an unresolved list as permission for every issuer.
    /// </summary>
    /// <param name="acceptedIssuers">The query's accepted-issuer items.</param>
    /// <returns>The accepted issuer ids, or <see langword="null"/> when the query places no issuer constraint.</returns>
    private static HashSet<string>? CollectAcceptedIssuerIds(ImmutableArray<QueryByExampleAcceptedIssuer> acceptedIssuers)
    {
        if(acceptedIssuers.IsDefaultOrEmpty)
        {
            return null;
        }

        HashSet<string> issuerIds = new(StringComparer.Ordinal);
        foreach(QueryByExampleAcceptedIssuer accepted in acceptedIssuers)
        {
            if(accepted.Id is { } directId)
            {
                _ = issuerIds.Add(directId);

                continue;
            }

            if(accepted.RecognizedInId is not null && !accepted.RecognizedIssuerIds.IsDefault)
            {
                issuerIds.UnionWith(accepted.RecognizedIssuerIds);
            }
        }

        return issuerIds;
    }


    /// <summary>
    /// Whether <paramref name="credential"/> is secured the way a Query By Example that constrains
    /// acceptedCryptosuites or acceptedEnvelopes accepts: acceptedCryptosuites names "which
    /// cryptographic proof suites the verifier will accept" and acceptedEnvelopes "which envelope
    /// formats the verifier will accept", the latter being "only applicable to enveloped credentials"
    /// and enabling "the holder to provide credentials in formats other than the default Data Integrity
    /// format" (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>).
    /// </summary>
    /// <remarks>
    /// A held <see cref="VerifiableCredential"/> is secured, if at all, by embedded Data Integrity
    /// proofs; an enveloped credential is not one of them, so acceptedEnvelopes admits none of these
    /// credentials by itself. A credential with no proof satisfies no securing constraint. A secured
    /// credential is accepted when acceptedCryptosuites is absent (the default Data Integrity format
    /// stays acceptable beside accepted envelopes), or when one of its proofs names an accepted suite:
    /// its <c>cryptosuite</c>, or its proof <c>type</c> for a legacy suite such as
    /// <c>Ed25519Signature2020</c> that carries no <c>cryptosuite</c>.
    /// </remarks>
    /// <param name="credential">The held credential.</param>
    /// <param name="acceptedCryptosuites">The accepted suite names, or <see langword="null"/> when acceptedCryptosuites is absent.</param>
    /// <returns><see langword="true"/> when the credential is secured as accepted.</returns>
    private static bool IsSecuredAsAccepted(VerifiableCredential credential, HashSet<string>? acceptedCryptosuites)
    {
        if(credential is not DataIntegritySecuredCredential { Proof: { Count: > 0 } proofs })
        {
            return false;
        }

        if(acceptedCryptosuites is null)
        {
            return true;
        }

        foreach(DataIntegrityProof proof in proofs)
        {
            if(acceptedCryptosuites.Contains(proof.Cryptosuite?.CryptosuiteName ?? proof.Type))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// The minimal disclosure of a Query By Example match: the requested <c>credentialSubject</c> field
    /// paths, since under the §3.4.2 selective-disclosure note "Any field included in a Query By Example
    /// is a required field". A type-only example discloses nothing claim-specific.
    /// </summary>
    /// <param name="example">The query's example, or <see langword="null"/> when it carries none.</param>
    /// <returns>The requested field paths.</returns>
    private static ImmutableArray<CredentialPath> RequestedDisclosurePaths(QueryByExampleCredential? example)
    {
        if(example is null || example.SubjectFields.IsEmpty)
        {
            return ImmutableArray<CredentialPath>.Empty;
        }

        ImmutableArray<CredentialPath>.Builder paths = ImmutableArray.CreateBuilder<CredentialPath>();
        foreach(KeyValuePair<string, string> field in example.SubjectFields)
        {
            JsonPointerType pointer = JsonPointerType.Root
                .Append(VcalmParameterNames.CredentialSubject)
                .Append(field.Key);
            paths.Add(new CredentialPath(pointer));
        }

        return paths.ToImmutable();
    }


    /// <summary>
    /// Evaluates a DigitalCredentialQueryLanguage entry, one of the query types of
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#requesting-a-presentation">VCALM §3.4</see>, through
    /// the existing <see cref="DcqlEvaluator"/>. A match's minimal disclosure is the matched claim
    /// patterns resolved to concrete credentialSubject paths.
    /// </summary>
    /// <param name="query">The DCQL entry.</param>
    /// <param name="heldCredentials">The credentials the holder holds.</param>
    /// <param name="metadataExtractor">The DCQL metadata extractor for the held credentials.</param>
    /// <param name="claimExtractor">The DCQL claim extractor for the held credentials.</param>
    /// <returns>The entry's match with every matching credential.</returns>
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


    /// <summary>Resolves the DCQL claim patterns that name a concrete path into credential paths; a pattern that does not is skipped.</summary>
    /// <param name="patterns">The matched claim patterns.</param>
    /// <returns>The resolved paths.</returns>
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


    /// <summary>
    /// Evaluates a DID Authentication query
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>): the holder satisfies it when it controls a DID of an accepted method AND, when
    /// the query constrains acceptedCryptosuites, can sign with one of "the cryptography suites among
    /// which the holder MUST choose when generating a cryptographic proof to be submitted to this
    /// verifier". The predicate is on the holder's DIDs and signing capability, not on held verifiable
    /// credentials. A constrained acceptedCryptosuites with no demonstrable holder cryptosuite fails
    /// closed: the holder cannot produce an acceptable proof, so the query is not satisfied.
    /// </summary>
    /// <param name="query">The DID Authentication entry.</param>
    /// <param name="holderDids">The holder's DIDs, or <see langword="null"/> when it offers none.</param>
    /// <param name="holderCryptosuites">The holder's cryptosuites, or <see langword="null"/> when it advertises none.</param>
    /// <returns>The entry's match.</returns>
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


    /// <summary>
    /// Whether the holder can produce a DID Authentication proof with one of the query's
    /// acceptedCryptosuites, "the cryptography suites among which the holder MUST choose when generating
    /// a cryptographic proof to be submitted to this verifier"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>). An empty array places no cryptosuite constraint (any suite is acceptable). When
    /// constrained, the holder must advertise at least one cryptosuite that is in the accepted set; a
    /// holder that advertises none (null/empty) cannot demonstrate an acceptable proof, so a constrained
    /// query fails closed.
    /// </summary>
    /// <param name="query">The DID Authentication entry.</param>
    /// <param name="holderCryptosuites">The holder's cryptosuites, or <see langword="null"/> when it advertises none.</param>
    /// <returns><see langword="true"/> when the holder can produce an accepted cryptosuite.</returns>
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


    /// <summary>Collects the IRI entries of the credential's <c>@context</c>; embedded context objects are not IRIs and are skipped.</summary>
    /// <param name="credential">The held credential.</param>
    /// <returns>The context IRIs.</returns>
    private static HashSet<string> CollectContexts(VerifiableCredential credential)
    {
        HashSet<string> contexts = new(StringComparer.Ordinal);
        if(credential.Context is null)
        {
            return contexts;
        }

        foreach(ContextEntry entry in credential.Context.Entries)
        {
            if(entry.IsIri)
            {
                _ = contexts.Add(entry.Iri!);
            }
        }

        return contexts;
    }


    /// <summary>Reads the first value of <paramref name="fieldName"/> across the credential's subjects.</summary>
    /// <param name="credential">The held credential.</param>
    /// <param name="fieldName">The subject field name.</param>
    /// <param name="value">The field's value when present.</param>
    /// <returns><see langword="true"/> when a subject carries the field.</returns>
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


    /// <summary>Compares a subject field value with the requested example value as ordinal text.</summary>
    /// <param name="actual">The credential's field value.</param>
    /// <param name="requested">The requested value.</param>
    /// <returns><see langword="true"/> when they are equal.</returns>
    private static bool ValueEquals(object? actual, string requested)
    {
        if(actual is string text)
        {
            return string.Equals(text, requested, StringComparison.Ordinal);
        }

        return string.Equals(actual?.ToString(), requested, StringComparison.Ordinal);
    }
}
