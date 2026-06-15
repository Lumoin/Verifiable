using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

namespace Verifiable.Vcalm;

/// <summary>
/// Typed <see cref="ExchangeContext"/> accessors for the W3C VCALM 1.0 §3.6.1 / §3.6.2 administration
/// endpoints — the per-request values the create-workflow endpoint stages between its
/// <c>BuildInputAsync</c> and its response (the minted workflow id and the workflow-metadata Location
/// URL). Each value is keyed by an interned string under the <c>vcalm.workflow.*</c> namespace,
/// mirroring how the Server / OAuth layers key their context slots.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class VcalmWorkflowContextExtensions
{
    private const string WorkflowIdKey = "vcalm.workflow.id";
    private const string WorkflowLocationKey = "vcalm.workflow.location";

    extension(ExchangeContext context)
    {
        /// <summary>The §3.6.1 <c>{localWorkflowId}</c> the create request minted / the resolver targets.</summary>
        public string? VcalmWorkflowId =>
            context.TryGetValue(WorkflowIdKey, out object? v) && v is string id ? id : null;

        /// <summary>Sets the §3.6.1 <c>{localWorkflowId}</c> on the request context.</summary>
        public void SetVcalmWorkflowId(string workflowId)
        {
            ArgumentException.ThrowIfNullOrEmpty(workflowId);
            context[WorkflowIdKey] = workflowId;
        }


        /// <summary>The §3.6.1 workflow-metadata URL composed for the create response's Location header.</summary>
        [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
            Justification = "The workflow-metadata URL is the verbatim string the deployment's endpoint-URI resolver composed; it rides through to the Location header unparsed.")]
        public string? VcalmWorkflowLocation =>
            context.TryGetValue(WorkflowLocationKey, out object? v) && v is string url ? url : null;

        /// <summary>Sets the §3.6.1 workflow-metadata Location URL on the request context.</summary>
        [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
            Justification = "The workflow-metadata URL is the verbatim string the deployment's endpoint-URI resolver composed; it is stored unparsed.")]
        public void SetVcalmWorkflowLocation(string location)
        {
            ArgumentException.ThrowIfNullOrEmpty(location);
            context[WorkflowLocationKey] = location;
        }
    }
}
