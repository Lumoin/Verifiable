namespace Verifiable.OAuth.Validation;

/// <summary>
/// What reading a claim of a verified claims set found, for a claim whose value has a shape of its own: absent, present in that
/// shape, or present in another. A present claim of another shape is never read as an absent one, nor filtered into the shape:
/// an <c>aud</c> array holding an element that is no string is no audience list (RFC 7519 section 4.1.3), whatever its other
/// elements name.
/// </summary>
internal enum ClaimReadResult
{
    /// <summary>The claim is not present.</summary>
    Absent,

    /// <summary>The claim is present in the shape its specification defines.</summary>
    Value,

    /// <summary>The claim is present in another shape.</summary>
    Malformed
}
