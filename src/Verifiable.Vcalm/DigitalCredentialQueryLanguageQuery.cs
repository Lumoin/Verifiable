using System.Diagnostics;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Vcalm;

/// <summary>
/// A §3.4 / §3.4.5 <c>DigitalCredentialQueryLanguage</c> query entry — the co-equal DCQL query type.
/// The entry carries the existing <see cref="Verifiable.Core.Model.Dcql.DcqlQuery"/> model verbatim;
/// VCALM does not redefine DCQL, it admits it as a peer of <see cref="QueryByExampleQuery"/>, so
/// <see cref="VprEvaluator"/> evaluates this entry through the existing
/// <see cref="Verifiable.Core.Dcql.DcqlEvaluator"/> rather than a VCALM-specific matcher.
/// </summary>
[DebuggerDisplay("DigitalCredentialQueryLanguage Group={Group}")]
public sealed record DigitalCredentialQueryLanguageQuery: VcalmPresentationQuery
{
    /// <summary>The carried DCQL query — the <c>Verifiable.Core</c> model, mapped not reimplemented.</summary>
    public required DcqlQuery Query { get; init; }
}
