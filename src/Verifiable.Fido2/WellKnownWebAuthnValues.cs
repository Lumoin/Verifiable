using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// Well-known WebAuthn string values fixed by
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">W3C Web Authentication Level 3,
/// section 5.11: Using Web Authentication across related origins</see>.
/// </summary>
public static class WellKnownWebAuthnValues
{
    /// <summary>The UTF-8 source literal of <see cref="RelatedOriginsWellKnownPath"/>.</summary>
    public static ReadOnlySpan<byte> RelatedOriginsWellKnownPathUtf8 => "/.well-known/webauthn"u8;

    /// <summary>
    /// The well-known path a relying party MUST host its <see cref="RelatedOriginsDocument"/> at, per
    /// section 5.11 ("A JSON document MUST be hosted at the <c>webauthn</c> well-known URL [RFC8615] for
    /// the RP ID") and the exact URL construction
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-validating-relation-origin">section 5.11.1</see>'s
    /// related origins validation procedure fetches (<c>https://&lt;rpId&gt;/.well-known/webauthn</c>):
    /// <c>/.well-known/webauthn</c>.
    /// </summary>
    /// <remarks>
    /// The content type the document MUST be served with (section 5.11: "The content type MUST be
    /// <c>application/json</c>") is not re-declared here — use the existing
    /// <see cref="Verifiable.JCose.WellKnownMediaTypes.Application.Json"/> constant, already reachable from
    /// this library.
    /// </remarks>
    public static readonly string RelatedOriginsWellKnownPath = Utf8Constants.ToInternedString(RelatedOriginsWellKnownPathUtf8);


    /// <summary>
    /// Determines whether <paramref name="path"/> is <see cref="RelatedOriginsWellKnownPath"/>.
    /// </summary>
    /// <param name="path">The path to test.</param>
    /// <returns><see langword="true"/> if <paramref name="path"/> is <see cref="RelatedOriginsWellKnownPath"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsRelatedOriginsWellKnownPath(string path) => Equals(RelatedOriginsWellKnownPath, path);


    /// <summary>
    /// Returns a value that indicates if the paths are the same.
    /// </summary>
    /// <param name="pathA">The first path to compare.</param>
    /// <param name="pathB">The second path to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="pathA"/> and <paramref name="pathB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string pathA, string pathB)
    {
        return object.ReferenceEquals(pathA, pathB) || StringComparer.Ordinal.Equals(pathA, pathB);
    }
}
