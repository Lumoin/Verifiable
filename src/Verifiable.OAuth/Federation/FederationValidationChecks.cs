using Verifiable.Core.Assessment;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// <see cref="ClaimDelegateAsync{TInput}"/>-shaped checks composing the
/// OpenID Federation 1.0 §3.2 (Entity Statement) and §10 (Trust Chain)
/// validation profiles in
/// <see cref="FederationValidationProfiles"/>. Each method reads the
/// piece of <see cref="EntityStatementValidationContext"/> or
/// <see cref="TrustChainValidationContext"/> it needs and emits a single
/// <see cref="Claim"/> with the corresponding
/// <see cref="WellKnownFederationClaimIds"/>.
/// </summary>
/// <remarks>
/// <para>
/// Checks are synchronous: any async work that depends on policy hooks —
/// key resolution, JWS signature verification, HTTP fetch — is performed
/// by the validator's orchestrator before this claim chain runs, and the
/// boolean outcomes are fed into the context. Mirrors the
/// <see cref="Verifiable.OAuth.Validation.ValidationChecks"/> precedent.
/// </para>
/// </remarks>
public static class FederationValidationChecks
{
    //Entity Statement checks (§3.2, codes 1100-1109).

    /// <summary>
    /// Asserts the JWS protected header carries an <c>alg</c> claim that is
    /// not <c>none</c>. RFC 7518 §3.6 forbids unsigned federation JWTs.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAlgPresent(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome =
            context.Header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algObj)
            && algObj is string alg
            && !string.IsNullOrWhiteSpace(alg)
            && !string.Equals(alg, WellKnownJwaValues.None, StringComparison.Ordinal)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.AlgPresent, outcome)]);
    }


    /// <summary>
    /// Asserts the JWS protected header's <c>typ</c> equals
    /// <see cref="WellKnownFederationMediaTypes.EntityStatementJwt"/> per
    /// RFC 8725 §3.11 explicit typing.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTypMatchesEntityStatement(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome =
            context.Header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
            && typObj is string typ
            && string.Equals(typ, WellKnownFederationMediaTypes.EntityStatementJwt, StringComparison.Ordinal)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.TypMatchesEntityStatement, outcome)]);
    }


    /// <summary>
    /// Asserts the payload carries an <c>iss</c> claim. Always Success when
    /// the statement reached this point — the parser refuses to construct
    /// an <see cref="EntityStatement"/> without <c>iss</c> — but the
    /// individual <see cref="Claim"/> is still emitted for the audit trail.
    /// </summary>
    public static ValueTask<List<Claim>> CheckIssPresent(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        //Statement.Issuer is non-default when parser succeeded; emit Success
        //for the audit trail so Federation §3.2 step "iss claim present" has
        //its dedicated record.
        ClaimOutcome outcome = !string.IsNullOrEmpty(context.Statement.Issuer.Value)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.IssPresent, outcome)]);
    }


    /// <summary>
    /// Asserts the payload carries a <c>sub</c> claim.
    /// </summary>
    public static ValueTask<List<Claim>> CheckSubPresent(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = !string.IsNullOrEmpty(context.Statement.Subject.Value)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.SubPresent, outcome)]);
    }


    /// <summary>
    /// Asserts the <c>iat</c> claim is within the
    /// <see cref="EntityStatementValidationContext.ClockSkew"/> window
    /// either side of <see cref="EntityStatementValidationContext.Now"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckIatInRange(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset iat = context.Statement.IssuedAt;
        ClaimOutcome outcome =
            iat >= context.Now - context.ClockSkew && iat <= context.Now + context.ClockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.IatInRange, outcome)]);
    }


    /// <summary>
    /// Asserts the <c>exp</c> claim is in the future relative to
    /// <see cref="EntityStatementValidationContext.Now"/> with
    /// <see cref="EntityStatementValidationContext.ClockSkew"/> tolerance.
    /// </summary>
    public static ValueTask<List<Claim>> CheckExpInFuture(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Statement.ExpiresAt > context.Now - context.ClockSkew
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ExpInFuture, outcome)]);
    }


    /// <summary>
    /// Asserts <c>exp</c> is strictly after <c>iat</c> — mutual temporal
    /// consistency independent of the clock. <c>exp</c> at or before <c>iat</c>
    /// is a non-positive lifetime and a structurally invalid statement.
    /// </summary>
    public static ValueTask<List<Claim>> CheckExpAfterIat(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Statement.ExpiresAt > context.Statement.IssuedAt
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ExpAfterIat, outcome)]);
    }


    /// <summary>
    /// Asserts the JWS signature verified against the key resolved for this
    /// statement. The verification itself happens in the validator's
    /// orchestrator before the claim chain runs; this check surfaces the
    /// pre-computed outcome via
    /// <see cref="EntityStatementValidationContext.SignatureVerified"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckSignatureVerifies(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.SignatureVerified
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.SignatureVerifies, outcome)]);
    }


    /// <summary>
    /// For an <see cref="EntityConfiguration"/> (self-issued), asserts the
    /// payload's <c>jwks</c> claim is present and carries at least one key.
    /// For a <see cref="SubordinateStatement"/> the check is
    /// <see cref="ClaimOutcome.NotApplicable"/> — superior-issued statements
    /// also carry <c>jwks</c> but the requirement attaches specifically to
    /// the self-issued shape per Federation §3.1.
    /// </summary>
    public static ValueTask<List<Claim>> CheckJwksPresentWhenSelfSigned(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(context.Statement is not EntityConfiguration)
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.JwksPresentWhenSelfSigned, ClaimOutcome.NotApplicable)]);
        }

        ClaimOutcome outcome = TryReadKeyCount(context.Statement.Payload, out int keyCount) && keyCount > 0
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.JwksPresentWhenSelfSigned, outcome)]);
    }


    /// <summary>
    /// When the payload's <c>jwks</c> is present, asserts no key carries
    /// private or symmetric key material — a published Entity Statement JWKS
    /// must contain only public keys. Private RSA/EC members (<c>d</c>,
    /// <c>p</c>, <c>q</c>, <c>dp</c>, <c>dq</c>, <c>qi</c>, <c>oth</c>) or a
    /// symmetric key value (<c>k</c>) is a key-leak defect.
    /// <see cref="ClaimOutcome.NotApplicable"/> when <c>jwks</c> is absent.
    /// </summary>
    public static ValueTask<List<Claim>> CheckJwksContainsNoPrivateOrSymmetricKeys(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryReadJwksKeys(context.Statement.Payload, out List<IReadOnlyDictionary<string, object>> keys))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.JwksContainsNoPrivateOrSymmetricKeys, ClaimOutcome.NotApplicable)]);
        }

        bool anyPrivate = false;
        foreach(IReadOnlyDictionary<string, object> key in keys)
        {
            if(WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember(key.Keys))
            {
                anyPrivate = true;
                break;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.JwksContainsNoPrivateOrSymmetricKeys,
                anyPrivate ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    /// <summary>
    /// When the payload's <c>jwks</c> is present, asserts that every key
    /// carries a unique, non-empty <c>kid</c> (Key ID) per OpenID Federation
    /// 1.0 §3.1 ("Every JWK in the JWK Set MUST have a unique kid value"). A
    /// missing or blank <c>kid</c> is a violation — key selection during
    /// signature verification relies on it — as is a duplicate.
    /// <see cref="ClaimOutcome.NotApplicable"/> when <c>jwks</c> is absent.
    /// </summary>
    public static ValueTask<List<Claim>> CheckJwksKeyIdsDistinct(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryReadJwksKeys(context.Statement.Payload, out List<IReadOnlyDictionary<string, object>> keys))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.JwksKeyIdsDistinct, ClaimOutcome.NotApplicable)]);
        }

        HashSet<string> seen = new(StringComparer.Ordinal);
        bool invalid = false;
        foreach(IReadOnlyDictionary<string, object> key in keys)
        {
            //§3.1: a kid is REQUIRED for every key (presence), and MUST be unique.
            //A missing/non-string/blank kid, or a duplicate, fails the check.
            if(!key.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                || kidObj is not string kid
                || string.IsNullOrEmpty(kid)
                || !seen.Add(kid))
            {
                invalid = true;
                break;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.JwksKeyIdsDistinct,
                invalid ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    /// <summary>
    /// Minimum RSA modulus length in bytes (2048 bits) a published Entity
    /// Statement key must meet.
    /// </summary>
    private const int MinimumRsaModulusBytes = 256;


    /// <summary>
    /// When the payload's <c>jwks</c> is present, asserts every RSA key
    /// carries a modulus of at least 2048 bits — a published Entity Statement
    /// must not advertise signing keys below contemporary minimum strength.
    /// The modulus length is derived from the base64url <c>n</c> member's
    /// string length (no decode needed). Non-RSA keys do not constrain this
    /// check; their strength is governed by the curve. Absent <c>jwks</c> is
    /// <see cref="ClaimOutcome.NotApplicable"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckJwksKeysMeetMinimumKeyLength(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryReadJwksKeys(context.Statement.Payload, out List<IReadOnlyDictionary<string, object>> keys))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.JwksKeysMeetMinimumKeyLength, ClaimOutcome.NotApplicable)]);
        }

        bool anyWeak = false;
        foreach(IReadOnlyDictionary<string, object> key in keys)
        {
            if(key.TryGetValue(WellKnownJwkMemberNames.Kty, out object? ktyObj)
                && ktyObj is string kty
                && string.Equals(kty, WellKnownKeyTypeValues.Rsa, StringComparison.Ordinal)
                && key.TryGetValue(WellKnownJwkMemberNames.N, out object? nObj)
                && nObj is string modulus
                && Base64UrlDecodedByteLength(modulus) < MinimumRsaModulusBytes)
            {
                anyWeak = true;
                break;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.JwksKeysMeetMinimumKeyLength,
                anyWeak ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    /// <summary>
    /// Computes the number of bytes a base64url string (no padding) decodes
    /// to, from its length alone — avoiding an allocation and a decoder
    /// dependency. A trailing group of 2 chars yields 1 byte, of 3 chars
    /// yields 2 bytes.
    /// </summary>
    private static int Base64UrlDecodedByteLength(string value)
    {
        int length = value.Length;
        int wholeGroups = length / 4;
        int remainder = length % 4;
        int bytes = wholeGroups * 3;
        bytes += remainder switch
        {
            2 => 1,
            3 => 2,
            _ => 0
        };

        return bytes;
    }


    /// <summary>
    /// When the payload's <c>authority_hints</c> claim is present, asserts
    /// it is a list of absolute-URL strings. Absent <c>authority_hints</c>
    /// is <see cref="ClaimOutcome.NotApplicable"/> — Trust Anchors omit the
    /// claim per Federation §3.1.1.
    /// </summary>
    public static ValueTask<List<Claim>> CheckAuthorityHintsWellFormed(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!context.Statement.Payload.TryGetValue(WellKnownFederationClaimNames.AuthorityHints, out object? hintsObj))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.AuthorityHintsWellFormed, ClaimOutcome.NotApplicable)]);
        }

        ClaimOutcome outcome = hintsObj switch
        {
            IEnumerable<object> items => AllAbsoluteUrlStrings(items) ? ClaimOutcome.Success : ClaimOutcome.Failure,
            _ => ClaimOutcome.Failure
        };

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.AuthorityHintsWellFormed, outcome)]);
    }


    /// <summary>
    /// When the payload's <c>metadata</c> claim is present, asserts it is a
    /// well-formed object keyed by entity-type strings and that no
    /// metadata value is <see langword="null"/> — Federation §5 prohibits
    /// <c>null</c> as a metadata value ("to prevent likely implementation
    /// errors caused by confusing members having null values with omitted
    /// members"), and §3.2 folds that into the metadata syntactic check. Both
    /// a <see langword="null"/> per-entity-type block and a <see langword="null"/>
    /// top-level member inside such a block fail. Absent <c>metadata</c> is
    /// <see cref="ClaimOutcome.NotApplicable"/> — pure intermediates need not
    /// declare any metadata.
    /// </summary>
    public static ValueTask<List<Claim>> CheckMetadataWellFormed(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!context.Statement.Payload.TryGetValue(WellKnownFederationClaimNames.Metadata, out object? metaObj))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.MetadataWellFormed, ClaimOutcome.NotApplicable)]);
        }

        ClaimOutcome outcome =
            metaObj is IReadOnlyDictionary<string, object> dict
            && AllNonEmptyKeys(dict)
            && NoNullMetadataValues(dict)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.MetadataWellFormed, outcome)]);
    }


    /// <summary>
    /// Asserts conditional claim placement per Federation §3.2 (steps deriving
    /// from §3.1.2 / §3.1.3). The Entity-Configuration-only claims
    /// (<c>authority_hints</c>, <c>trust_anchor_hints</c>, <c>trust_marks</c>,
    /// <c>trust_mark_issuers</c>, <c>trust_mark_owners</c>) MUST NOT appear in a
    /// <see cref="SubordinateStatement"/>, and the Subordinate-Statement-only
    /// claims (<c>metadata_policy</c>, <c>metadata_policy_crit</c>,
    /// <c>constraints</c>, <c>source_endpoint</c>) MUST NOT appear in an
    /// <see cref="EntityConfiguration"/>. A misplaced claim is a structurally
    /// invalid statement and a policy-injection vector — an
    /// <c>EntityConfiguration</c> carrying <c>metadata_policy</c> would be a
    /// self-asserted policy that the spec confines to superior-issued
    /// Subordinate Statements.
    /// </summary>
    public static ValueTask<List<Claim>> CheckClaimPlacement(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        UnverifiedJwtPayload payload = context.Statement.Payload;
        bool misplaced;
        if(context.Statement is EntityConfiguration)
        {
            //Subordinate-Statement-only claims must not appear in a self-issued
            //Entity Configuration (§3.1.3).
            misplaced =
                payload.TryGetValue(WellKnownFederationClaimNames.MetadataPolicy, out _)
                || payload.TryGetValue(WellKnownFederationClaimNames.MetadataPolicyCrit, out _)
                || payload.TryGetValue(WellKnownFederationClaimNames.Constraints, out _)
                || payload.TryGetValue(WellKnownFederationClaimNames.SourceEndpoint, out _);
        }
        else
        {
            //Entity-Configuration-only claims must not appear in a
            //superior-issued Subordinate Statement (§3.1.2).
            misplaced =
                payload.TryGetValue(WellKnownFederationClaimNames.AuthorityHints, out _)
                || payload.TryGetValue(WellKnownFederationClaimNames.TrustAnchorHints, out _)
                || payload.TryGetValue(WellKnownFederationClaimNames.TrustMarks, out _)
                || payload.TryGetValue(WellKnownFederationClaimNames.TrustMarkIssuers, out _)
                || payload.TryGetValue(WellKnownFederationClaimNames.TrustMarkOwners, out _);
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ClaimPlacementValid,
                misplaced ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    /// <summary>
    /// Asserts the <c>crit</c> (critical) payload claim, when present, is
    /// well-formed and every extension Claim Name it lists is present in the
    /// payload and declared understood via
    /// <see cref="EntityStatementValidationContext.UnderstoodCriticalClaims"/>,
    /// per Federation §13.4 (§3.1.1 usage). A <c>crit</c> that is not a
    /// non-empty array of strings, repeats a name, names a claim the
    /// specification already defines for this JWT type (crit is for extensions
    /// only), lists a name absent from the payload, or names an extension the
    /// consumer does not understand invalidates the statement.
    /// <see cref="ClaimOutcome.NotApplicable"/> when <c>crit</c> is absent.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCritClaimsUnderstood(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        UnverifiedJwtPayload payload = context.Statement.Payload;
        if(!payload.TryGetValue(WellKnownFederationClaimNames.Crit, out object? critObj))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.CritClaimsUnderstood, ClaimOutcome.NotApplicable)]);
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.CritClaimsUnderstood,
                CritSatisfied(critObj, payload, context.UnderstoodCriticalClaims)
                    ? ClaimOutcome.Success
                    : ClaimOutcome.Failure)]);
    }


    //The claim names Federation 1.0 (with RFC 7519) specifies for use in an
    //Entity Statement. §13.4 / §3.1.1 reserve crit for EXTENSION claims NOT
    //defined by the spec, so a crit entry naming one of these is a producer
    //MUST NOT. The standard JWT claims plus the top-level federation claims;
    //sub-structure names (keys, the constraints sub-claims), metadata-block
    //parameters, and the trust_chain / peer_trust_chain JOSE header parameters
    //are intentionally excluded — they are not top-level Entity Statement
    //claims, and omitting one only ever under-rejects (never a false positive,
    //since every listed name is genuinely spec-defined). Local to the check.
    private static readonly HashSet<string> SpecifiedEntityStatementClaimNames =
        new(StringComparer.Ordinal)
        {
            WellKnownJwtClaimNames.Iss, WellKnownJwtClaimNames.Sub, WellKnownJwtClaimNames.Aud,
            WellKnownJwtClaimNames.Exp, WellKnownJwtClaimNames.Nbf, WellKnownJwtClaimNames.Iat,
            WellKnownJwtClaimNames.Jti,
            WellKnownFederationClaimNames.Jwks, WellKnownFederationClaimNames.AuthorityHints,
            WellKnownFederationClaimNames.TrustAnchorHints, WellKnownFederationClaimNames.Metadata,
            WellKnownFederationClaimNames.MetadataPolicy, WellKnownFederationClaimNames.MetadataPolicyCrit,
            WellKnownFederationClaimNames.Constraints, WellKnownFederationClaimNames.TrustMarks,
            WellKnownFederationClaimNames.TrustMarkIssuers, WellKnownFederationClaimNames.TrustMarkOwners,
            WellKnownFederationClaimNames.SourceEndpoint, WellKnownFederationClaimNames.Crit,
            WellKnownFederationClaimNames.TrustAnchor
        };


    /// <summary>
    /// The §13.4 rule set over the <c>crit</c> claim value: a non-empty array of
    /// distinct strings, each an EXTENSION claim that is present in the payload,
    /// is not a claim name the specification already defines for this JWT type
    /// (§3.1.1 — crit is for extensions only), and that the consumer declares
    /// understood.
    /// </summary>
    private static bool CritSatisfied(
        object critValue, UnverifiedJwtPayload payload, IReadOnlySet<string> understood)
    {
        if(critValue is not IEnumerable<object> items)
        {
            return false;
        }

        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach(object item in items)
        {
            if(item is not string name || string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            if(!seen.Add(name))
            {
                //Duplicate name — a producer MUST NOT per §13.4.
                return false;
            }

            if(SpecifiedEntityStatementClaimNames.Contains(name))
            {
                //crit is for EXTENSION claims only (§3.1.1); naming a claim the
                //specification already defines for this JWT type is a producer
                //MUST NOT per §13.4.
                return false;
            }

            if(!payload.TryGetValue(name, out _))
            {
                //A crit entry MUST occur as a claim in the JWT (§13.4).
                return false;
            }

            if(!understood.Contains(name))
            {
                //A critical extension the recipient does not understand makes
                //the JWT invalid (§13.4).
                return false;
            }
        }

        //The empty array is forbidden (§13.4); seen is empty only when items was empty.
        return seen.Count > 0;
    }


    /// <summary>
    /// Asserts the statement's JWS protected header carries neither
    /// <c>trust_chain</c> nor <c>peer_trust_chain</c>, per Federation §4.3 /
    /// §4.4. An Entity Configuration or Subordinate Statement is an integral
    /// component of a Trust Chain and MUST NOT embed one in its own header —
    /// a statement that does is malformed and a potential chain-confusion
    /// vector.
    /// </summary>
    public static ValueTask<List<Claim>> CheckNoChainHeaderInStatement(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        bool present =
            context.Header.TryGetValue(WellKnownFederationClaimNames.TrustChain, out _)
            || context.Header.TryGetValue(WellKnownFederationClaimNames.PeerTrustChain, out _);

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.NoChainHeaderInStatement,
                present ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    //The federation_entity endpoint metadata keys whose URL values §5.1.1 constrains to
    //https-with-no-fragment. Local to this check.
    private static readonly string[] FederationEntityEndpointKeys =
    [
        FederationMetadataParameterNames.FetchEndpoint,
        FederationMetadataParameterNames.ListEndpoint,
        FederationMetadataParameterNames.ResolveEndpoint,
        FederationMetadataParameterNames.TrustMarkStatusEndpoint,
        FederationMetadataParameterNames.TrustMarkListEndpoint,
        FederationMetadataParameterNames.TrustMarkEndpoint,
        FederationMetadataParameterNames.HistoricalKeysEndpoint
    ];


    /// <summary>
    /// When the statement's <c>metadata</c> carries a <c>federation_entity</c>
    /// block, asserts every federation endpoint URL it declares uses the
    /// <c>https</c> scheme and contains no fragment component, per Federation
    /// §5.1.1. A present endpoint value that is not such a URL fails.
    /// <see cref="ClaimOutcome.NotApplicable"/> when there is no
    /// <c>federation_entity</c> metadata block.
    /// </summary>
    public static ValueTask<List<Claim>> CheckFederationEntityEndpointsWellFormed(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryReadFederationEntityMetadata(context.Statement.Payload, out IReadOnlyDictionary<string, object> federationEntity))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.FederationEntityEndpointsWellFormed, ClaimOutcome.NotApplicable)]);
        }

        bool malformed = false;
        foreach(string endpointKey in FederationEntityEndpointKeys)
        {
            if(federationEntity.TryGetValue(endpointKey, out object? value) && !IsHttpsUrlWithoutFragment(value))
            {
                malformed = true;
                break;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.FederationEntityEndpointsWellFormed,
                malformed ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    /// <summary>
    /// When the statement's <c>metadata</c> carries a <c>federation_entity</c>
    /// block whose <c>endpoint_auth_signing_alg_values_supported</c> array is
    /// present, asserts none of its listed algorithms is <c>none</c>, per
    /// Federation §5.1.1 (the value <c>none</c> MUST NOT be used for the
    /// <c>private_key_jwt</c> JWT authenticating to federation endpoints).
    /// <see cref="ClaimOutcome.NotApplicable"/> when there is no
    /// <c>federation_entity</c> metadata block.
    /// </summary>
    public static ValueTask<List<Claim>> CheckFederationEntityEndpointAuthAlgsNotNone(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryReadFederationEntityMetadata(context.Statement.Payload, out IReadOnlyDictionary<string, object> federationEntity))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.FederationEntityEndpointAuthAlgsNotNone, ClaimOutcome.NotApplicable)]);
        }

        bool listsNone =
            federationEntity.TryGetValue(FederationMetadataParameterNames.EndpointAuthSigningAlgValuesSupported, out object? value)
            && value is IEnumerable<object> algs
            && AnyAlgIsNone(algs);

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.FederationEntityEndpointAuthAlgsNotNone,
                listsNone ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    /// <summary>
    /// Whether any element of <paramref name="algs"/> is the JWS <c>none</c>
    /// algorithm, which Federation §5.1.1 forbids in
    /// <c>endpoint_auth_signing_alg_values_supported</c>. Non-string elements
    /// are not this check's concern and are skipped.
    /// </summary>
    private static bool AnyAlgIsNone(IEnumerable<object> algs)
    {
        foreach(object alg in algs)
        {
            if(alg is string s && WellKnownJwaValues.IsNone(s))
            {
                return true;
            }
        }

        return false;
    }


    //The §5.2.1 JWK-set metadata parameters that MUST NOT appear under
    //federation_entity metadata (the Federation Entity Keys live in the Entity
    //Statement's top-level jwks Claim, not in the metadata block). Local to the
    //check below.
    private static readonly string[] FederationEntityForbiddenJwkSetParams =
    [
        FederationMetadataParameterNames.Jwks,
        FederationMetadataParameterNames.JwksUri,
        FederationMetadataParameterNames.SignedJwksUri
    ];


    /// <summary>
    /// When the statement's <c>metadata</c> carries a <c>federation_entity</c>
    /// block, asserts none of the §5.2.1 JWK-set parameters (<c>jwks</c>,
    /// <c>jwks_uri</c>, <c>signed_jwks_uri</c>) appears in it, per Federation
    /// §5.2.1 (those parameters MUST NOT be used in <c>federation_entity</c>
    /// metadata). <see cref="ClaimOutcome.NotApplicable"/> when there is no
    /// <c>federation_entity</c> metadata block.
    /// </summary>
    public static ValueTask<List<Claim>> CheckFederationEntityHasNoJwkSetParams(
        EntityStatementValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryReadFederationEntityMetadata(context.Statement.Payload, out IReadOnlyDictionary<string, object> federationEntity))
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.FederationEntityHasNoJwkSetParams, ClaimOutcome.NotApplicable)]);
        }

        bool present = false;
        foreach(string forbidden in FederationEntityForbiddenJwkSetParams)
        {
            if(federationEntity.ContainsKey(forbidden))
            {
                present = true;
                break;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.FederationEntityHasNoJwkSetParams,
                present ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    //Trust Chain checks (§4.3 / §10, codes 1120-1125).

    /// <summary>
    /// Asserts position 0 of the chain is the subject's
    /// <see cref="EntityConfiguration"/> (self-issued; <c>iss</c> == <c>sub</c>).
    /// </summary>
    public static ValueTask<List<Claim>> CheckChainStartsAtSubject(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome =
            context.Chain.Statements.Count > 0
            && context.Chain.Statements[0] is EntityConfiguration
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainStartsAtSubject, outcome)]);
    }


    /// <summary>
    /// Asserts the final position of the chain is an
    /// <see cref="EntityConfiguration"/> whose <see cref="EntityStatement.Issuer"/>
    /// appears in
    /// <see cref="TrustChainValidationContext.TrustAnchors"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckChainTerminatesAtTrustAnchor(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.Chain.Statements.Count > 0
            && context.Chain.Statements[^1] is EntityConfiguration terminal
            && context.TrustAnchors.Contains(terminal.Issuer))
        {
            outcome = ClaimOutcome.Success;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainTerminatesAtTrustAnchor, outcome)]);
    }


    /// <summary>
    /// Asserts the chain contains no cycles per Federation §10.2. A cycle
    /// is detected when any non-self-issued statement (a Subordinate
    /// Statement, where <c>iss</c> != <c>sub</c>) has the same
    /// <see cref="EntityStatement.Subject"/> as another non-self-issued
    /// statement, or when the same <see cref="EntityStatement.Issuer"/>
    /// appears in two non-self-issued statements.
    /// </summary>
    /// <remarks>
    /// Self-issued statements (Entity Configurations at positions 0 and
    /// N-1) are excluded from the cycle check by design — the leaf's EC
    /// and the anchor's SS-about-the-leaf both legitimately name the leaf
    /// as <c>sub</c>; that is the expected chain shape, not a cycle.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckChainNoCycles(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        HashSet<string> seenSubjects = new(StringComparer.Ordinal);
        HashSet<string> seenIssuers = new(StringComparer.Ordinal);
        bool cycle = false;
        foreach(EntityStatement s in context.Chain.Statements)
        {
            //Skip self-issued statements (Entity Configurations). A chain
            //may carry the leaf's EC at position 0 and the anchor's EC at
            //position N-1; neither contributes to cycle detection because
            //the iss == sub relationship is the spec-defined self-signature.
            if(string.Equals(s.Issuer.Value, s.Subject.Value, StringComparison.Ordinal))
            {
                continue;
            }

            if(!seenSubjects.Add(s.Subject.Value) || !seenIssuers.Add(s.Issuer.Value))
            {
                cycle = true;
                break;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainNoCycles, cycle ? ClaimOutcome.Failure : ClaimOutcome.Success)]);
    }


    /// <summary>
    /// Asserts every adjacent pair in the chain is properly linked per
    /// Federation §10.2: for each position <c>j</c> from 0 to <c>i-1</c>,
    /// <c>Statements[j].iss</c> equals <c>Statements[j+1].sub</c> — the
    /// statement at <c>j</c> is issued by the entity the statement at
    /// <c>j+1</c> is about. A break means the supplied statements do not form a
    /// single path from the subject to the Trust Anchor, even if every
    /// individual signature verified.
    /// </summary>
    public static ValueTask<List<Claim>> CheckChainProperlyLinked(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<EntityStatement> statements = context.Chain.Statements;
        ClaimOutcome outcome = ClaimOutcome.Success;
        for(int j = 0; j + 1 < statements.Count; j++)
        {
            if(!string.Equals(statements[j].Issuer.Value, statements[j + 1].Subject.Value, StringComparison.Ordinal))
            {
                outcome = ClaimOutcome.Failure;
                break;
            }
        }

        //A zero- or single-statement chain has no adjacency to break; the
        //start/terminate checks govern whether it is a usable chain at all.
        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainProperlyLinked, outcome)]);
    }


    /// <summary>
    /// Asserts the chain length does not exceed the
    /// <c>max_path_length</c> constraint accumulated up the chain per
    /// Federation §6.2. The constraint applies to the number of
    /// intermediates between the subject and the constraint-bearing
    /// statement; this check walks every Subordinate Statement's
    /// <c>constraints.max_path_length</c> (when present) and verifies that
    /// the remaining hops to the subject do not exceed it.
    /// </summary>
    public static ValueTask<List<Claim>> CheckChainWithinMaxPathLength(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Success;
        IReadOnlyList<EntityStatement> statements = context.Chain.Statements;
        //Walk from position 1 up (Subordinate Statements and Trust Anchor).
        //Each statement at position i constrains the number of intermediates
        //between itself and the subject: (i - 1) intermediates exist between
        //position 0 (subject) and position i. The statement's
        //max_path_length permits at most that many.
        for(int i = 1; i < statements.Count; i++)
        {
            if(!TryReadMaxPathLength(statements[i].Payload, out int maxPathLength))
            {
                continue;
            }

            int intermediatesBelow = i - 1;
            if(intermediatesBelow > maxPathLength)
            {
                outcome = ClaimOutcome.Failure;
                break;
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainWithinMaxPathLength, outcome)]);
    }


    /// <summary>
    /// Asserts every link's signature verified against the key resolved at
    /// the next position up. The chain validator performs the verification
    /// before the claim chain runs and records the per-link outcome in
    /// <see cref="TrustChainValidationContext.LinkSignaturesVerified"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckChainAllLinksVerified(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.LinkSignaturesVerified.Count == context.Chain.Statements.Count
            && context.LinkSignaturesVerified.Count > 0)
        {
            outcome = ClaimOutcome.Success;
            foreach(bool verified in context.LinkSignaturesVerified)
            {
                if(!verified)
                {
                    outcome = ClaimOutcome.Failure;
                    break;
                }
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainAllLinksVerified, outcome)]);
    }


    /// <summary>
    /// Asserts the chain's effective expiry is in the future relative to
    /// <see cref="TrustChainValidationContext.Now"/> with
    /// <see cref="TrustChainValidationContext.ClockSkew"/> tolerance,
    /// using the minimum of the per-statement <c>exp</c> claims per
    /// Federation §10.4.
    /// </summary>
    public static ValueTask<List<Claim>> CheckChainExpIsMinOfLinks(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.Chain.Statements.Count > 0)
        {
            DateTimeOffset effectiveExp = context.Chain.Statements[0].ExpiresAt;
            for(int i = 1; i < context.Chain.Statements.Count; i++)
            {
                DateTimeOffset linkExp = context.Chain.Statements[i].ExpiresAt;
                if(linkExp < effectiveExp)
                {
                    effectiveExp = linkExp;
                }
            }

            outcome = effectiveExp > context.Now - context.ClockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainExpIsMinOfLinks, outcome)]);
    }


    //Sub-field names of a naming_constraints object (Federation §6.2.2). Local to
    //this check — they are not standalone protocol claims.
    private const string NamingConstraintsPermitted = "permitted";
    private const string NamingConstraintsExcluded = "excluded";


    /// <summary>
    /// Asserts every subordinate Entity Identifier in the chain satisfies the
    /// <c>naming_constraints</c> carried by any superior Subordinate Statement above
    /// it, per Federation §6.2.2. Each constraining statement applies to the subjects
    /// of all statements below it (the entities subordinate to it). Matching uses the
    /// RFC 5280 §4.2.1.10 host-name constraint syntax against the host of each
    /// identifier: a leading <c>.</c> matches any sub-domain (<c>.example.com</c>
    /// matches <c>host.example.com</c> but not <c>example.com</c>), otherwise the host
    /// must match exactly. An <c>excluded</c> match invalidates the chain regardless of
    /// <c>permitted</c>; when <c>permitted</c> is present and non-empty the host must
    /// match at least one entry. Chains without <c>naming_constraints</c> are
    /// vacuously <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckChainSatisfiesNamingConstraints(
        TrustChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<EntityStatement> statements = context.Chain.Statements;
        ClaimOutcome outcome = ClaimOutcome.Success;

        for(int i = 0; i < statements.Count && outcome == ClaimOutcome.Success; i++)
        {
            if(!TryReadNamingConstraints(statements[i].Payload, out List<string> permitted, out List<string> excluded))
            {
                continue;
            }

            //The constraint binds every entity subordinate to the constraining
            //statement — the subjects of all statements below it (positions < i).
            for(int j = 0; j < i; j++)
            {
                string host = ExtractUriHost(statements[j].Subject.Value);
                if(host.Length == 0)
                {
                    continue;
                }

                if(HostMatchesAny(host, excluded))
                {
                    outcome = ClaimOutcome.Failure;
                    break;
                }

                if(permitted.Count > 0 && !HostMatchesAny(host, permitted))
                {
                    outcome = ClaimOutcome.Failure;
                    break;
                }
            }
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.ChainSatisfiesNamingConstraints, outcome)]);
    }


    //Trust Mark checks (§7.3, codes 1170 / 1172). Chain-aware checks
    //(1171 issuer authorization, 1173 delegation validity) live on their
    //own static evaluators because their context is the trust chain plus
    //the mark, not the mark alone.

    /// <summary>
    /// Asserts the trust mark's JWS signature verified against the
    /// issuer's resolved key. The verification itself happens in the
    /// orchestrator before the claim chain runs; this check surfaces the
    /// pre-computed outcome via
    /// <see cref="TrustMarkValidationContext.SignatureVerified"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTrustMarkSignatureVerifies(
        TrustMarkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.SignatureVerified
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.TrustMarkSignatureVerifies, outcome)]);
    }


    /// <summary>
    /// Asserts the trust mark's <c>exp</c> claim, if present, is in the
    /// future relative to <see cref="TrustMarkValidationContext.Now"/>
    /// with <see cref="TrustMarkValidationContext.ClockSkew"/> tolerance.
    /// When the mark omits <c>exp</c> the check is
    /// <see cref="ClaimOutcome.NotApplicable"/> — §7.1.1 permits indefinite
    /// validity.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTrustMarkExpInFuture(
        TrustMarkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(context.Mark.ExpiresAt is null)
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.TrustMarkExpInFuture, ClaimOutcome.NotApplicable)]);
        }

        ClaimOutcome outcome = context.Mark.ExpiresAt.Value > context.Now - context.ClockSkew
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.TrustMarkExpInFuture, outcome)]);
    }


    /// <summary>
    /// Asserts the trust mark's <c>exp</c>, when present, is strictly after
    /// <c>iat</c> — mutual temporal consistency independent of the clock.
    /// <see cref="ClaimOutcome.NotApplicable"/> when the mark omits <c>exp</c>
    /// (§7.1.1 permits indefinite validity).
    /// </summary>
    public static ValueTask<List<Claim>> CheckTrustMarkExpAfterIat(
        TrustMarkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(context.Mark.ExpiresAt is not { } exp)
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(WellKnownFederationClaimIds.TrustMarkExpAfterIat, ClaimOutcome.NotApplicable)]);
        }

        ClaimOutcome outcome = exp > context.Mark.IssuedAt
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.TrustMarkExpAfterIat, outcome)]);
    }


    /// <summary>
    /// Asserts the trust mark's JWS protected header carries an <c>alg</c>
    /// that is present and not <c>none</c>, per Federation §7.3 — an unsigned
    /// trust mark is rejected just as an entity statement is.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTrustMarkAlgPresent(
        TrustMarkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome =
            context.Header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algObj)
            && algObj is string alg
            && !string.IsNullOrWhiteSpace(alg)
            && !string.Equals(alg, WellKnownJwaValues.None, StringComparison.Ordinal)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.TrustMarkAlgPresent, outcome)]);
    }


    /// <summary>
    /// Asserts the trust mark's <c>iat</c> is within the
    /// <see cref="TrustMarkValidationContext.ClockSkew"/> window either side of
    /// <see cref="TrustMarkValidationContext.Now"/> — its issuance time is in
    /// the past, per Federation §7.3.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTrustMarkIatInRange(
        TrustMarkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset iat = context.Mark.IssuedAt;
        ClaimOutcome outcome =
            iat >= context.Now - context.ClockSkew && iat <= context.Now + context.ClockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownFederationClaimIds.TrustMarkIatInRange, outcome)]);
    }


    //Helpers.

    private static bool TryReadKeyCount(UnverifiedJwtPayload payload, out int count)
    {
        count = 0;
        if(!payload.TryGetValue(WellKnownFederationClaimNames.Jwks, out object? jwksObj))
        {
            return false;
        }

        if(jwksObj is IReadOnlyDictionary<string, object> jwksDict
            && jwksDict.TryGetValue(WellKnownJwkMemberNames.Keys, out object? keysObj)
            && keysObj is IEnumerable<object> keys)
        {
            foreach(object _ in keys)
            {
                count++;
            }

            return true;
        }

        return false;
    }


    private static bool TryReadJwksKeys(
        UnverifiedJwtPayload payload, out List<IReadOnlyDictionary<string, object>> keys)
    {
        keys = [];
        if(!payload.TryGetValue(WellKnownFederationClaimNames.Jwks, out object? jwksObj))
        {
            return false;
        }

        if(jwksObj is IReadOnlyDictionary<string, object> jwksDict
            && jwksDict.TryGetValue(WellKnownJwkMemberNames.Keys, out object? keysObj)
            && keysObj is IEnumerable<object> keyItems)
        {
            foreach(object item in keyItems)
            {
                if(item is IReadOnlyDictionary<string, object> key)
                {
                    keys.Add(key);
                }
            }

            return true;
        }

        return false;
    }


    private static bool TryReadMaxPathLength(UnverifiedJwtPayload payload, out int maxPathLength)
    {
        maxPathLength = 0;
        if(!payload.TryGetValue(WellKnownFederationClaimNames.Constraints, out object? constraintsObj)
            || constraintsObj is not IReadOnlyDictionary<string, object> constraints
            || !constraints.TryGetValue(WellKnownFederationClaimNames.MaxPathLength, out object? mplObj))
        {
            return false;
        }

        switch(mplObj)
        {
            case int i:
                maxPathLength = i;
                return maxPathLength >= 0;
            case long l when l >= 0 && l <= int.MaxValue:
                maxPathLength = (int)l;
                return true;
            default:
                return false;
        }
    }


    private static bool AllAbsoluteUrlStrings(IEnumerable<object> items)
    {
        foreach(object item in items)
        {
            if(item is not string s
                || string.IsNullOrWhiteSpace(s)
                || !Uri.TryCreate(s, UriKind.Absolute, out _))
            {
                return false;
            }
        }

        return true;
    }


    private static bool AllNonEmptyKeys(IReadOnlyDictionary<string, object> dict)
    {
        foreach(string key in dict.Keys)
        {
            if(string.IsNullOrWhiteSpace(key))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Reads the <c>federation_entity</c> metadata block from the payload's <c>metadata</c> claim.
    /// Returns <see langword="false"/> when there is no <c>metadata</c> object or no
    /// <c>federation_entity</c> member that is itself an object.
    /// </summary>
    private static bool TryReadFederationEntityMetadata(
        UnverifiedJwtPayload payload, out IReadOnlyDictionary<string, object> federationEntity)
    {
        federationEntity = EmptyMetadataBlock;
        if(payload.TryGetValue(WellKnownFederationClaimNames.Metadata, out object? metaObj)
            && metaObj is IReadOnlyDictionary<string, object> metadata
            && metadata.TryGetValue(WellKnownEntityTypeIdentifiers.FederationEntity.Value, out object? feObj)
            && feObj is IReadOnlyDictionary<string, object> fe)
        {
            federationEntity = fe;
            return true;
        }

        return false;
    }


    /// <summary>The shared empty block returned when no federation_entity metadata is present.</summary>
    private static readonly IReadOnlyDictionary<string, object> EmptyMetadataBlock =
        new Dictionary<string, object>(0);


    /// <summary>
    /// Whether <paramref name="value"/> is a string holding an absolute URL that uses the <c>https</c>
    /// scheme and carries no fragment component, per Federation §5.1.1. A non-string, relative, non-https,
    /// or fragment-bearing value is rejected.
    /// </summary>
    private static bool IsHttpsUrlWithoutFragment(object? value)
    {
        return value is string s
            && Uri.TryCreate(s, UriKind.Absolute, out Uri? uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            && string.IsNullOrEmpty(uri.Fragment);
    }


    /// <summary>
    /// Whether the <c>metadata</c> object carries no <see langword="null"/> value: neither a
    /// <see langword="null"/> per-entity-type block nor a <see langword="null"/> top-level member
    /// inside such a block, per Federation §5 (a JSON <c>null</c> deserializes to a
    /// <see langword="null"/> entry).
    /// </summary>
    private static bool NoNullMetadataValues(IReadOnlyDictionary<string, object> metadata)
    {
        foreach(KeyValuePair<string, object> entityType in metadata)
        {
            if(entityType.Value is null)
            {
                return false;
            }

            if(entityType.Value is IReadOnlyDictionary<string, object> typeMetadata)
            {
                foreach(KeyValuePair<string, object> member in typeMetadata)
                {
                    if(member.Value is null)
                    {
                        return false;
                    }
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Reads <c>constraints.naming_constraints</c> into its <c>permitted</c> /
    /// <c>excluded</c> string lists. Returns <see langword="false"/> when the statement
    /// carries no <c>naming_constraints</c>; the lists are empty (never <see langword="null"/>)
    /// when a member is absent.
    /// </summary>
    private static bool TryReadNamingConstraints(
        UnverifiedJwtPayload payload, out List<string> permitted, out List<string> excluded)
    {
        permitted = [];
        excluded = [];

        if(!payload.TryGetValue(WellKnownFederationClaimNames.Constraints, out object? constraintsObj)
            || constraintsObj is not IReadOnlyDictionary<string, object> constraints
            || !constraints.TryGetValue(WellKnownFederationClaimNames.NamingConstraints, out object? namingObj)
            || namingObj is not IReadOnlyDictionary<string, object> naming)
        {
            return false;
        }

        ReadStringList(naming, NamingConstraintsPermitted, permitted);
        ReadStringList(naming, NamingConstraintsExcluded, excluded);
        return true;
    }


    /// <summary>
    /// Appends the non-empty string elements of <paramref name="source"/>'s
    /// <paramref name="key"/> array member to <paramref name="target"/>. Non-string and
    /// blank elements are skipped; a missing or non-array member contributes nothing.
    /// </summary>
    private static void ReadStringList(
        IReadOnlyDictionary<string, object> source, string key, List<string> target)
    {
        if(source.TryGetValue(key, out object? listObj) && listObj is IEnumerable<object> items)
        {
            foreach(object item in items)
            {
                if(item is string value && !string.IsNullOrWhiteSpace(value))
                {
                    target.Add(value);
                }
            }
        }
    }


    /// <summary>
    /// Extracts the host of an absolute-URI Entity Identifier, or the empty string when
    /// the value is not an absolute URI. Case folding is left to the case-insensitive
    /// comparison in <see cref="HostMatchesConstraint"/>.
    /// </summary>
    private static string ExtractUriHost(string entityIdentifier)
    {
        return Uri.TryCreate(entityIdentifier, UriKind.Absolute, out Uri? uri)
            ? uri.Host
            : string.Empty;
    }


    /// <summary>
    /// Whether <paramref name="host"/> matches at least one entry in
    /// <paramref name="constraints"/> per <see cref="HostMatchesConstraint"/>.
    /// </summary>
    private static bool HostMatchesAny(string host, List<string> constraints)
    {
        foreach(string constraint in constraints)
        {
            if(HostMatchesConstraint(host, constraint))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// RFC 5280 §4.2.1.10 host-name constraint matching (Federation §6.2.2): a leading
    /// <c>.</c> matches any sub-domain but not the bare domain (<c>.example.com</c>
    /// matches <c>host.example.com</c>, not <c>example.com</c>); otherwise the host must
    /// match exactly. Case-insensitive per DNS.
    /// </summary>
    private static bool HostMatchesConstraint(string host, string constraint)
    {
        if(string.IsNullOrEmpty(constraint))
        {
            return false;
        }

        return constraint[0] == '.'
            ? host.EndsWith(constraint, StringComparison.OrdinalIgnoreCase)
            : string.Equals(host, constraint, StringComparison.OrdinalIgnoreCase);
    }
}
