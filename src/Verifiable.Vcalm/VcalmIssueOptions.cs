using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The parsed §3.2.1 <c>options</c> object of a <c>POST /credentials/issue</c> request. §2.4: every
/// option is OPTIONAL; an instance MAY prohibit some and MAY require others. All members default to
/// absent.
/// </summary>
[DebuggerDisplay("VcalmIssueOptions CredentialId={CredentialId} MandatoryPointers={MandatoryPointers.Length}")]
public sealed record VcalmIssueOptions
{
    /// <summary>
    /// §3.2.1 <c>options.credentialId</c>: a URI identifying the issued credential in later APIs.
    /// "If credentialId is not provided …, the issuer service will auto-populate its value from
    /// credential.id." <see langword="null"/> when absent.
    /// </summary>
    public string? CredentialId { get; init; }

    /// <summary>
    /// Whether the request carried a <c>credentialId</c> member (distinguishing an explicit
    /// <c>null</c>/empty value from absence for the §3.2.1 SHOULD-NOT-both-set rule).
    /// </summary>
    public bool HasCredentialId { get; init; }

    /// <summary>
    /// §3.2.1 <c>options.mandatoryPointers</c>: the mandatory-reveal JSON pointers a
    /// selective-disclosure suite bakes into the base proof. Empty when absent.
    /// </summary>
    public ImmutableArray<string> MandatoryPointers { get; init; } = ImmutableArray<string>.Empty;

    /// <summary>Whether the request carried a <c>mandatoryPointers</c> member.</summary>
    public bool HasMandatoryPointers { get; init; }
}
