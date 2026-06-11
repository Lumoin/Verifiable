using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// ID Token type values for the SIOPv2 <c>id_token_type</c> request parameter and the
/// <c>id_token_types_supported</c> OP metadata parameter per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-6.1">SIOPv2 §6.1</see>.
/// </summary>
/// <remarks>
/// The RP determines which type it actually received by comparing the <c>iss</c> and
/// <c>sub</c> claim values (SIOPv2 §11.1): equal values mean a subject-signed
/// (Self-Issued) ID Token. The default when neither side states a type is
/// <see cref="AttesterSignedIdToken"/>.
/// </remarks>
[DebuggerDisplay("SiopIdTokenTypes")]
public static class SiopIdTokenTypes
{
    /// <summary>The UTF-8 source literal of <see cref="SubjectSignedIdToken"/>.</summary>
    public static ReadOnlySpan<byte> SubjectSignedIdTokenUtf8 => "subject_signed_id_token"u8;

    /// <summary>
    /// The <c>subject_signed_id_token</c> type — a Self-Issued ID Token, signed with
    /// key material under the End-User's control.
    /// </summary>
    public static readonly string SubjectSignedIdToken = Utf8Constants.ToInternedString(SubjectSignedIdTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AttesterSignedIdToken"/>.</summary>
    public static ReadOnlySpan<byte> AttesterSignedIdTokenUtf8 => "attester_signed_id_token"u8;

    /// <summary>
    /// The <c>attester_signed_id_token</c> type — an ID Token issued by the party
    /// operating the OP, i.e. the classical ID Token of OpenID Connect Core.
    /// </summary>
    public static readonly string AttesterSignedIdToken = Utf8Constants.ToInternedString(AttesterSignedIdTokenUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>subject_signed_id_token</c>.</summary>
    public static bool IsSubjectSignedIdToken(string value) =>
        string.Equals(value, SubjectSignedIdToken, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>attester_signed_id_token</c>.</summary>
    public static bool IsAttesterSignedIdToken(string value) =>
        string.Equals(value, AttesterSignedIdToken, StringComparison.Ordinal);


    /// <summary>
    /// Returns the canonical form of a well-known ID Token type value, or the
    /// original value when not recognized. Comparison is case-sensitive.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsSubjectSignedIdToken(value) => SubjectSignedIdToken,
        _ when IsAttesterSignedIdToken(value) => AttesterSignedIdToken,
        _ => value
    };
}
