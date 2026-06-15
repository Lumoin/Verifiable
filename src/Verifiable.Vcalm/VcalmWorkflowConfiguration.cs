using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a W3C VCALM 1.0 §3.6.1 workflow configuration — the
/// admin-authored step graph the §3.6.3 create-exchange endpoint instantiates an exchange on. The
/// JSON-side parser materializes it so the <c>Verifiable.Vcalm</c> serialization firewall keeps
/// <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// <para>
/// §3.6.1: a workflow carries an OPTIONAL <c>id</c>, the REQUIRED <c>initialStep</c> (the step an
/// exchange starts on), the REQUIRED <c>steps</c> object (each <c>STEP_NAME</c> keying its step data),
/// an OPTIONAL <c>credentialTemplates</c> array (the templates an <c>issueRequests</c> step evaluates),
/// an OPTIONAL <c>controller</c> (the zcap root controller, modeled-but-deferred to V-7), and an
/// OPTIONAL <c>authorization</c> object (OAuth2 / zcap config, modeled — enforcement deferred to V-7).
/// </para>
/// <para>
/// The step graph here is the LINEAR <c>nextStep</c> chain: a step has at most one <c>nextStep</c>
/// (BRANCHING / REPEAT graphs are out of scope). The exchange walks <c>initialStep</c> →
/// <c>nextStep</c> → … until a step with no <c>nextStep</c> (the final step) completes it.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmWorkflowConfiguration Id={Id} InitialStep={InitialStep} Steps={Steps.Count}")]
public sealed record VcalmWorkflowConfiguration
{
    /// <summary>
    /// The §3.6.1 OPTIONAL <c>id</c> the workflow is created with, or <see langword="null"/> when the
    /// request omits it (the create endpoint mints one through the host-generic identifier seam).
    /// </summary>
    public string? Id { get; init; }

    /// <summary>
    /// The §3.6.1 REQUIRED <c>initialStep</c> — the name of the step an exchange on this workflow
    /// starts on. Validated to name a defined member of <see cref="Steps"/>.
    /// </summary>
    public required string InitialStep { get; init; }

    /// <summary>
    /// The §3.6.1 REQUIRED <c>steps</c> object — each <c>STEP_NAME</c> keying its step data. Ordered
    /// by the wire's member order; a step's <see cref="VcalmWorkflowStep.NextStep"/> names another key.
    /// </summary>
    public required ImmutableDictionary<string, VcalmWorkflowStep> Steps { get; init; }

    /// <summary>
    /// The §3.6.1 OPTIONAL <c>credentialTemplates</c> array — the templates an <c>issueRequests</c>
    /// step evaluates against the exchange variables to mint a credential. Empty when the workflow
    /// issues no credentials.
    /// </summary>
    public ImmutableArray<VcalmCredentialTemplate> CredentialTemplates { get; init; } =
        ImmutableArray<VcalmCredentialTemplate>.Empty;

    /// <summary>
    /// The §3.6.1 OPTIONAL <c>controller</c> — the zcap root controller of the instance. Modeled and
    /// carried verbatim; zcap authorization enforcement is deferred to V-7.
    /// </summary>
    public string? Controller { get; init; }

    /// <summary>
    /// The §3.6.1 OPTIONAL <c>authorization</c> object (verbatim JSON) — the OAuth2 / zcap
    /// authorization-scheme config. Modeled and carried verbatim; the authorization field's ENFORCEMENT
    /// (zcap in particular) is deferred to V-7, so the value is round-tripped through §3.6.2 but not
    /// acted on by the exchange engine.
    /// </summary>
    public string? AuthorizationJson { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.6.1 → HTTP 400).</summary>
    public static VcalmWorkflowConfiguration Malformed() =>
        new()
        {
            InitialStep = string.Empty,
            Steps = ImmutableDictionary<string, VcalmWorkflowStep>.Empty,
            Failure = VcalmParseFailure.Malformed
        };


    /// <summary>Creates an unknown-member parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmWorkflowConfiguration UnknownOption() =>
        new()
        {
            InitialStep = string.Empty,
            Steps = ImmutableDictionary<string, VcalmWorkflowStep>.Empty,
            Failure = VcalmParseFailure.UnknownOption
        };
}
