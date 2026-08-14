using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One of the two sets of signature applicability rules of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1 clause 4.1</see>, carrying the Annex A object identifier the set is allocated
/// and the fixed revocation freshness value REQ-4.2-03 c) ii) keys off the set.
/// </summary>
/// <remarks>
/// The set is closed by construction: clause 4.1 defines exactly two rule sets and the private constructor
/// keeps it that way. The freshness pairing is the specification's, deliberate and counterintuitive-looking:
/// <see cref="RealTimeRequired"/> accepts revocation status information up to 24 hours old so a basic
/// signature can be answered from the latest published CRL right away (NOTE 4 of REQ-4.2-03), while
/// <see cref="RealTimeNotRequired"/> accepts a maximum age of zero because the relying party has agreed to
/// wait — up to 24 hours — for revocation status information issued at or after the validation time.
/// </remarks>
[DebuggerDisplay("EuSignatureApplicabilityRuleSet: {PolicyOid}")]
public sealed record EuSignatureApplicabilityRuleSet
{
    /// <summary>Creates a rule set; private so the clause 4.1 enumeration stays closed.</summary>
    /// <param name="policyOid">The Annex A object identifier allocated to the set.</param>
    /// <param name="maximumAcceptedRevocationFreshness">The REQ-4.2-03 c) ii) freshness value.</param>
    private EuSignatureApplicabilityRuleSet(string policyOid, TimeSpan maximumAcceptedRevocationFreshness)
    {
        PolicyOid = policyOid;
        MaximumAcceptedRevocationFreshness = maximumAcceptedRevocationFreshness;
    }

    /// <summary>The dotted-decimal Annex A object identifier allocated to this rule set.</summary>
    public string PolicyOid { get; }

    /// <summary>
    /// The maximum accepted revocation freshness REQ-4.2-03 c) ii) fixes for the signing certificate under
    /// this rule set, applied as
    /// <see cref="X509ValidationConstraints.MaximumAcceptedRevocationFreshness"/>.
    /// </summary>
    public TimeSpan MaximumAcceptedRevocationFreshness { get; }


    /// <summary>
    /// The <c>id-etsi-sarc-realTimeReq</c> rule set (clause 4.1 set 1): for contexts where a real time
    /// validation response is required and basic signatures are acceptable. Freshness is 24 hours
    /// (REQ-4.2-03 c) ii) 1)).
    /// </summary>
    public static EuSignatureApplicabilityRuleSet RealTimeRequired { get; } =
        new(WellKnownOids.SignatureApplicabilityRulesRealTimeRequired, TimeSpan.FromHours(24));

    /// <summary>
    /// The <c>id-etsi-sarc-realTimeNotReq</c> rule set (clause 4.1 set 2): for contexts where a validation
    /// response delay of up to 24 hours is acceptable, or the minimum acceptable class of signature is a
    /// signature with time. Freshness is zero (REQ-4.2-03 c) ii) 2)).
    /// </summary>
    public static EuSignatureApplicabilityRuleSet RealTimeNotRequired { get; } =
        new(WellKnownOids.SignatureApplicabilityRulesRealTimeNotRequired, TimeSpan.Zero);
}


/// <summary>
/// The fixed vocabulary of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1 clause 4.5</see> applicability rules checking reports.
/// </summary>
public static class SignatureApplicabilityRulesWellKnown
{
    /// <summary>
    /// The scope text REQ-4.5-01 a) requires every applicability rules checking report to carry: the
    /// specification's own heading followed by its description of what was checked.
    /// </summary>
    public static string ScopeStatement { get; } =
        "Signature applicability rules checking (validation rules) for European qualified electronic "
        + "signatures/seals using trusted lists: validation of digital signature to identify whether it can "
        + "be considered technically suitable to implement a European qualified electronic signature/seal "
        + "using EUMS trusted lists in the sense of the applicable European legislation at the time of "
        + "signing, i.e. either Directive 1999/93/EC or Regulation (EU) No 910/2014.";

    /// <summary>
    /// The rules-source name a report states when cryptographic security issues were expressed against
    /// ETSI TS 119 312 rather than national rules — the indication REQ-4.2-03 e) and REQ-4.5-01 h) require
    /// to be made clearly.
    /// </summary>
    public static string CryptographicSuitesSpecificationRulesSource { get; } = "ETSI TS 119 312";
}
