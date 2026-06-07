using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// A single OpenID AuthZEN Authorization API 1.0 Access Evaluation request —
/// the question "may this <see cref="Subject"/> perform this
/// <see cref="Action"/> on this <see cref="Resource"/> in this
/// <see cref="Context"/>?" posed by a Policy Enforcement Point to a Policy
/// Decision Point.
/// </summary>
/// <remarks>
/// The library parses the inbound JSON body into this neutral shape via the
/// application-supplied
/// <see cref="Server.ParseAccessEvaluationRequestDelegate"/> (the
/// <c>Verifiable.OAuth</c> serialization firewall keeps STJ out of the
/// library), then hands it to the PDP seam
/// <see cref="Server.EvaluateAccessDelegate"/>.
/// </remarks>
[DebuggerDisplay("AccessEvaluationRequest {Subject.Id,nq} {Action.Name,nq} {Resource.Id,nq}")]
public sealed record AccessEvaluationRequest
{
    /// <summary>The principal whose access is being evaluated. Required.</summary>
    public required AuthZenSubject Subject { get; init; }

    /// <summary>The operation the subject seeks to perform. Required.</summary>
    public required AuthZenAction Action { get; init; }

    /// <summary>The protected object access is evaluated against. Required.</summary>
    public required AuthZenResource Resource { get; init; }

    /// <summary>
    /// Free-form request context the PDP policy may consult (time, IP, device
    /// posture, transaction details, …). Optional.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Context { get; init; }
}
