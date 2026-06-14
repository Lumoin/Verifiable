using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// Validates a W3C VCALM 1.0 §3.6.1 workflow configuration's step graph against the §3.6.1 structural
/// MUSTs the library enforces, mapping a violation to the §3.8 ProblemDetail the §3.6.1 create endpoint
/// answers with a 400.
/// </summary>
/// <remarks>
/// §3.6.1 invariants checked here:
/// <list type="bullet">
///   <item><description><c>initialStep</c> is present and names a defined step.</description></item>
///   <item><description>each step's <c>nextStep</c>, when present, names a defined step.</description></item>
///   <item><description>
///     a step that is reached as a FINAL step (no successor; the walk terminates on it) carries no
///     <c>nextStep</c> — §3.6.1: "This field MUST NOT be present on the final step configuration."
///     The library reads the LINEAR chain from <c>initialStep</c>; the chain's terminal step is the
///     final step, and it MUST NOT carry a <c>nextStep</c> (a non-null <c>nextStep</c> on a terminal
///     step is a contradiction the walk would otherwise treat as a dangling reference, already caught
///     by the next-step-defined check; the final-step rule is the stronger statement of the same MUST).
///   </description></item>
/// </list>
/// The §3.6.1 step graph here is the LINEAR <c>nextStep</c> chain (no branching), so the final step is
/// well defined: it is the unique step reachable from <c>initialStep</c> that has no <c>nextStep</c>.
/// </remarks>
[DebuggerDisplay("VcalmWorkflowValidation")]
public static class VcalmWorkflowValidation
{
    /// <summary>
    /// Validates <paramref name="configuration"/>. Returns <see langword="null"/> when the
    /// configuration is structurally valid, or the §3.8 ProblemDetail describing the first §3.6.1
    /// violation when it is not (the §3.6.1 create endpoint answers it with a 400).
    /// </summary>
    /// <param name="configuration">The parsed workflow configuration to validate.</param>
    /// <returns>The validation ProblemDetail, or <see langword="null"/> when valid.</returns>
    public static VcalmProblemDetail? Validate(VcalmWorkflowConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        //§3.6.1: steps is REQUIRED and non-empty (an exchange needs at least one step to run).
        if(configuration.Steps.Count == 0)
        {
            return Invalid("A workflow MUST define at least one step (§3.6.1 steps is REQUIRED).");
        }

        //§3.6.1: initialStep is REQUIRED and MUST name a defined step.
        if(string.IsNullOrEmpty(configuration.InitialStep))
        {
            return Invalid("A workflow MUST specify an initialStep (§3.6.1 initialStep is REQUIRED).");
        }

        if(!configuration.Steps.ContainsKey(configuration.InitialStep))
        {
            return Invalid(
                $"The workflow's initialStep '{configuration.InitialStep}' does not name a defined step (§3.6.1).");
        }

        //§3.6.1: each step's nextStep, when present, MUST name a defined step.
        foreach(KeyValuePair<string, VcalmWorkflowStep> entry in configuration.Steps)
        {
            string? nextStep = entry.Value.NextStep;
            if(nextStep is not null && !configuration.Steps.ContainsKey(nextStep))
            {
                return Invalid(
                    $"Step '{entry.Key}' names a nextStep '{nextStep}' that does not name a defined step (§3.6.1).");
            }
        }

        //§3.6.1: "This field MUST NOT be present on the final step configuration." The final step is the
        //terminal of the LINEAR chain from initialStep — the step the walk ends on. Walk the chain and
        //confirm the terminal step carries no nextStep; a cycle is independently a configuration error
        //(it has no final step at all).
        VcalmProblemDetail? walkProblem = ValidateLinearChain(configuration);
        if(walkProblem is not null)
        {
            return walkProblem;
        }

        return null;
    }


    //Walks the LINEAR nextStep chain from initialStep. The terminal step (no nextStep) is the §3.6.1
    //final step and MUST NOT carry a nextStep — that is true by construction of "terminal". The walk's
    //purpose is to detect a CYCLE (a malformed chain with no final step), which the §3.6.1 step graph
    //(a finite linear chain) MUST NOT contain — a cycle is the same defect the multi-step exchange
    //engine caps at runtime, rejected here at configuration time.
    private static VcalmProblemDetail? ValidateLinearChain(VcalmWorkflowConfiguration configuration)
    {
        HashSet<string> visited = new(StringComparer.Ordinal);
        string current = configuration.InitialStep;

        while(true)
        {
            if(!visited.Add(current))
            {
                return Invalid(
                    $"The workflow's step graph contains a cycle reaching '{current}' — the §3.6.1 nextStep chain MUST be linear and terminate on a final step.");
            }

            if(!configuration.Steps.TryGetValue(current, out VcalmWorkflowStep? step))
            {
                //Already guaranteed by the next-step-defined check above; defensive.
                return Invalid($"The workflow's step graph references an undefined step '{current}' (§3.6.1).");
            }

            if(step.NextStep is null)
            {
                //The terminal step — the §3.6.1 final step — carries no nextStep, as required.
                return null;
            }

            current = step.NextStep;
        }
    }


    private static VcalmProblemDetail Invalid(string detail) =>
        VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            detail);
}
