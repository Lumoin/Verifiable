namespace Verifiable.Fido2;

/// <summary>
/// The <c>prf</c> extension's one or two evaluation salts, shared by both the registration-side and
/// the assertion-side input records.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues">W3C Web
/// Authentication Level 3, section 10.1.4: Pseudo-random function extension (prf)</see>, dictionary
/// <c>AuthenticationExtensionsPRFValues</c>: <c>first</c> is required, <c>second</c> is optional — a
/// second evaluation in the same ceremony operation, evaluated only when supplied. These are the
/// relying party's own salts, not secrets, so they are carried the same way the library carries the
/// other opaque byte inputs of these options types (see <see cref="Fido2LargeBlobAssertionExtensionInput.Write"/>):
/// a <see cref="TaggedMemory{T}"/> wrapping the caller's bytes rather than a naked buffer.
/// </remarks>
public sealed record Fido2PrfValues
{
    /// <summary>
    /// The first (and, absent <see cref="Second"/>, only) PRF evaluation input.
    /// </summary>
    public required TaggedMemory<byte> First { get; init; }

    /// <summary>
    /// A second PRF evaluation input evaluated in the same ceremony operation, or
    /// <see langword="null"/> when only one evaluation is requested.
    /// </summary>
    public TaggedMemory<byte>? Second { get; init; }
}
