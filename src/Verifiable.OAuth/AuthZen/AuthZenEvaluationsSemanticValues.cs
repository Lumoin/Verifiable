using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// Wire VALUES for the <c>options.evaluations_semantic</c> field of an OpenID
/// AuthZEN Authorization API 1.0 Access Evaluations API request, with
/// recognisers and a neutral <see cref="TryParse"/> to map a wire string to
/// the <see cref="AuthZenEvaluationsSemantic"/> enum the library branches on.
/// </summary>
/// <remarks>
/// These are the wire string VALUES (e.g. <c>"deny_on_first_deny"</c>), the
/// AuthZEN analogue of the value side of a parameter-names class. An
/// application's request parser maps the inbound string through
/// <see cref="TryParse"/>; the helpers never throw and carry no policy —
/// an unrecognised value yields <see langword="false"/> and the caller
/// (strict per spec) rejects it.
/// </remarks>
[DebuggerDisplay("AuthZenEvaluationsSemanticValues")]
public static class AuthZenEvaluationsSemanticValues
{
    /// <summary>The UTF-8 source literal of <see cref="ExecuteAll"/>.</summary>
    public static ReadOnlySpan<byte> ExecuteAllUtf8 => "execute_all"u8;

    /// <summary><c>execute_all</c> — <see cref="AuthZenEvaluationsSemantic.ExecuteAll"/>.</summary>
    public static readonly string ExecuteAll = Utf8Constants.ToInternedString(ExecuteAllUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DenyOnFirstDeny"/>.</summary>
    public static ReadOnlySpan<byte> DenyOnFirstDenyUtf8 => "deny_on_first_deny"u8;

    /// <summary><c>deny_on_first_deny</c> — <see cref="AuthZenEvaluationsSemantic.DenyOnFirstDeny"/>.</summary>
    public static readonly string DenyOnFirstDeny = Utf8Constants.ToInternedString(DenyOnFirstDenyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PermitOnFirstPermit"/>.</summary>
    public static ReadOnlySpan<byte> PermitOnFirstPermitUtf8 => "permit_on_first_permit"u8;

    /// <summary><c>permit_on_first_permit</c> — <see cref="AuthZenEvaluationsSemantic.PermitOnFirstPermit"/>.</summary>
    public static readonly string PermitOnFirstPermit = Utf8Constants.ToInternedString(PermitOnFirstPermitUtf8);


    /// <summary>Whether <paramref name="value"/> is the <c>execute_all</c> wire value.</summary>
    public static bool IsExecuteAll(string? value) =>
        string.Equals(value, ExecuteAll, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is the <c>deny_on_first_deny</c> wire value.</summary>
    public static bool IsDenyOnFirstDeny(string? value) =>
        string.Equals(value, DenyOnFirstDeny, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is the <c>permit_on_first_permit</c> wire value.</summary>
    public static bool IsPermitOnFirstPermit(string? value) =>
        string.Equals(value, PermitOnFirstPermit, StringComparison.Ordinal);


    /// <summary>
    /// Maps a <c>evaluations_semantic</c> wire string to its
    /// <see cref="AuthZenEvaluationsSemantic"/>. Returns <see langword="true"/>
    /// on a recognised value; <see langword="false"/> otherwise (the caller
    /// rejects an unrecognised semantic).
    /// </summary>
    public static bool TryParse(string? value, out AuthZenEvaluationsSemantic semantic)
    {
        if(IsExecuteAll(value)) { semantic = AuthZenEvaluationsSemantic.ExecuteAll; return true; }
        if(IsDenyOnFirstDeny(value)) { semantic = AuthZenEvaluationsSemantic.DenyOnFirstDeny; return true; }
        if(IsPermitOnFirstPermit(value)) { semantic = AuthZenEvaluationsSemantic.PermitOnFirstPermit; return true; }

        semantic = AuthZenEvaluationsSemantic.ExecuteAll;
        return false;
    }
}
