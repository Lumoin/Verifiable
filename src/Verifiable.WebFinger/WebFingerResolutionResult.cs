using System;

namespace Verifiable.WebFinger;

/// <summary>
/// The outcome of a WebFinger client resolution: either the resolved <see cref="JsonResourceDescriptor"/>
/// or a <see cref="WebFingerResolutionError"/>. Fail-closed by return, not by exception — a failed HTTPS
/// fetch or a malformed body yields a <see cref="Failure"/> result, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.2">RFC 7033 §4.2</see>.
/// </summary>
public sealed record WebFingerResolutionResult
{
    /// <summary>The resolved descriptor when successful; otherwise <see langword="null"/>.</summary>
    public JsonResourceDescriptor? Jrd { get; init; }

    /// <summary>The failure diagnostic when unsuccessful; otherwise <see langword="null"/>.</summary>
    public WebFingerResolutionError? Error { get; init; }

    /// <summary>Whether resolution produced a descriptor.</summary>
    public bool IsSuccessful => Error is null && Jrd is not null;


    /// <summary>Creates a successful result carrying the resolved descriptor.</summary>
    /// <param name="jrd">The resolved JSON Resource Descriptor.</param>
    public static WebFingerResolutionResult Success(JsonResourceDescriptor jrd)
    {
        ArgumentNullException.ThrowIfNull(jrd);

        return new WebFingerResolutionResult { Jrd = jrd };
    }


    /// <summary>Creates a failed result carrying the diagnostic.</summary>
    /// <param name="error">The failure diagnostic; use a member of <see cref="WebFingerResolutionErrors"/>.</param>
    public static WebFingerResolutionResult Failure(WebFingerResolutionError error)
    {
        ArgumentNullException.ThrowIfNull(error);

        return new WebFingerResolutionResult { Error = error };
    }
}
