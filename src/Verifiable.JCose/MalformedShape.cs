using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token whose classification failed: structurally inconsistent input,
/// malformed Base64Url, or a header that does not parse to a JSON object.
/// </summary>
/// <remarks>
/// <para>
/// Returned by <see cref="JoseTokenClassifier.ClassifyAsync"/> when the
/// input fails the structural-classification preconditions for any of the
/// recognized shapes. <see cref="Reason"/> is intended for logging and
/// metrics, not for inclusion in HTTP error response bodies — exposing the
/// parser's failure mode to attackers leaks information about the
/// classifier's internals.
/// </para>
/// <para>
/// <strong>Stable reason strings.</strong>
/// The classifier uses a small fixed set of reason strings that downstream
/// metrics and logs can aggregate over without regular-expression scraping.
/// Application classifiers that derive additional malformed cases should
/// follow the same convention.
/// </para>
/// </remarks>
/// <param name="Reason">
/// A short, stable description of why classification failed, suitable for
/// logging and metrics.
/// </param>
[DebuggerDisplay("MalformedShape Reason={Reason,nq}")]
public sealed record MalformedShape(string Reason): JoseTokenShape;
