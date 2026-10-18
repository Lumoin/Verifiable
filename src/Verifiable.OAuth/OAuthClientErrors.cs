using Verifiable.Cryptography.Text;
using Verifiable.OAuth.AuthCode;


namespace Verifiable.OAuth;

/// <summary>
/// The error codes this library's client sets on a refusal of its own judgement, which no OAuth specification defines.
/// </summary>
/// <remarks>
/// <para>
/// A code of this table is never one an authorization server sends and never one an authorization server of this library
/// answers with, so it stands apart from the specification-defined codes of <see cref="OAuthErrors"/>: a refusal carrying
/// one is always constructed with <see cref="AuthCodeFlowRefusalOrigin.ClientJudgement"/>, and the code tells the
/// application which judgement of the client refused, not what an authorization server answered.
/// </para>
/// </remarks>
public static class OAuthClientErrors
{
    /// <summary>The UTF-8 source literal of <see cref="InvalidResponse"/>.</summary>
    public static ReadOnlySpan<byte> InvalidResponseUtf8 => "invalid_response"u8;

    /// <summary>
    /// The authorization server's response was read, but a field it carries holds a value the specification of that
    /// response does not allow, such as an <c>expires_in</c> that is not a positive integer or a <c>request_uri</c> that is
    /// not an absolute URI. The client refuses the response on its own judgement; no specification defines this code.
    /// </summary>
    public static string InvalidResponse { get; } = Utf8Constants.ToInternedString(InvalidResponseUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UnrecognisedRefusal"/>.</summary>
    public static ReadOnlySpan<byte> UnrecognisedRefusalUtf8 => "unrecognised_refusal"u8;

    /// <summary>
    /// The client refused on a judgement of a kind the mapping it was answered through does not name: a refusal case added to
    /// the library after the mapping was written. It is named so, never answered under a category established for another case,
    /// so the application sees that the refusal is of no kind it was told of. No specification defines this code.
    /// </summary>
    public static string UnrecognisedRefusal { get; } = Utf8Constants.ToInternedString(UnrecognisedRefusalUtf8);
}
