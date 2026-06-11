using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// Wire field NAMES for the OpenID AuthZEN Authorization API 1.0 Access
/// Evaluation request and response JSON bodies. The library hand-builds the
/// response through these names (preserving the <c>Verifiable.OAuth</c>
/// serialization firewall); an application's request parser reads the same
/// names off the inbound JSON.
/// </summary>
/// <remarks>
/// These are the NAMES of the information-model fields, not their values —
/// the AuthZEN analogue of <see cref="OAuthRequestParameterNames"/>. Values
/// are deployment data (subject ids, resource ids, action names, policy
/// context).
/// </remarks>
[DebuggerDisplay("AuthZenFieldNames")]
public static class AuthZenFieldNames
{
    /// <summary>The UTF-8 source literal of <see cref="Subject"/>.</summary>
    public static ReadOnlySpan<byte> SubjectUtf8 => "subject"u8;

    /// <summary><c>subject</c> — the Subject entity of an Access Evaluation request.</summary>
    public static readonly string Subject = Utf8Constants.ToInternedString(SubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Resource"/>.</summary>
    public static ReadOnlySpan<byte> ResourceUtf8 => "resource"u8;

    /// <summary><c>resource</c> — the Resource entity of an Access Evaluation request.</summary>
    public static readonly string Resource = Utf8Constants.ToInternedString(ResourceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Action"/>.</summary>
    public static ReadOnlySpan<byte> ActionUtf8 => "action"u8;

    /// <summary><c>action</c> — the Action entity of an Access Evaluation request.</summary>
    public static readonly string Action = Utf8Constants.ToInternedString(ActionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Context"/>.</summary>
    public static ReadOnlySpan<byte> ContextUtf8 => "context"u8;

    /// <summary><c>context</c> — the request Context object, or the per-decision response context.</summary>
    public static readonly string Context = Utf8Constants.ToInternedString(ContextUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary><c>type</c> — the type of a Subject or Resource entity.</summary>
    public static readonly string Type = Utf8Constants.ToInternedString(TypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary><c>id</c> — the identifier of a Subject or Resource entity.</summary>
    public static readonly string Id = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Name"/>.</summary>
    public static ReadOnlySpan<byte> NameUtf8 => "name"u8;

    /// <summary><c>name</c> — the name of an Action entity.</summary>
    public static readonly string Name = Utf8Constants.ToInternedString(NameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Properties"/>.</summary>
    public static ReadOnlySpan<byte> PropertiesUtf8 => "properties"u8;

    /// <summary><c>properties</c> — the free-form property bag of a Subject, Resource, or Action.</summary>
    public static readonly string Properties = Utf8Constants.ToInternedString(PropertiesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Decision"/>.</summary>
    public static ReadOnlySpan<byte> DecisionUtf8 => "decision"u8;

    /// <summary><c>decision</c> — the boolean Decision of an Access Evaluation response.</summary>
    public static readonly string Decision = Utf8Constants.ToInternedString(DecisionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Evaluations"/>.</summary>
    public static ReadOnlySpan<byte> EvaluationsUtf8 => "evaluations"u8;

    /// <summary>
    /// <c>evaluations</c> — the array of per-item requests (Access Evaluations
    /// API request) or per-item decisions (response).
    /// </summary>
    public static readonly string Evaluations = Utf8Constants.ToInternedString(EvaluationsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Options"/>.</summary>
    public static ReadOnlySpan<byte> OptionsUtf8 => "options"u8;

    /// <summary><c>options</c> — the options object of an Access Evaluations API request.</summary>
    public static readonly string Options = Utf8Constants.ToInternedString(OptionsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EvaluationsSemantic"/>.</summary>
    public static ReadOnlySpan<byte> EvaluationsSemanticUtf8 => "evaluations_semantic"u8;

    /// <summary>
    /// <c>evaluations_semantic</c> — the batch evaluation semantic inside the
    /// <c>options</c> object. See <see cref="AuthZenEvaluationsSemanticValues"/>.
    /// </summary>
    public static readonly string EvaluationsSemantic = Utf8Constants.ToInternedString(EvaluationsSemanticUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Results"/>.</summary>
    public static ReadOnlySpan<byte> ResultsUtf8 => "results"u8;

    /// <summary><c>results</c> — the result array of a Search API response.</summary>
    public static readonly string Results = Utf8Constants.ToInternedString(ResultsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Page"/>.</summary>
    public static ReadOnlySpan<byte> PageUtf8 => "page"u8;

    /// <summary><c>page</c> — the pagination object of a Search API request or response.</summary>
    public static readonly string Page = Utf8Constants.ToInternedString(PageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Token"/>.</summary>
    public static ReadOnlySpan<byte> TokenUtf8 => "token"u8;

    /// <summary><c>token</c> — the request page token (opaque continuation from a prior response).</summary>
    public static readonly string Token = Utf8Constants.ToInternedString(TokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Limit"/>.</summary>
    public static ReadOnlySpan<byte> LimitUtf8 => "limit"u8;

    /// <summary><c>limit</c> — the request page size limit (maximum results).</summary>
    public static readonly string Limit = Utf8Constants.ToInternedString(LimitUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NextToken"/>.</summary>
    public static ReadOnlySpan<byte> NextTokenUtf8 => "next_token"u8;

    /// <summary><c>next_token</c> — the response page continuation token; empty string signals the end.</summary>
    public static readonly string NextToken = Utf8Constants.ToInternedString(NextTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Count"/>.</summary>
    public static ReadOnlySpan<byte> CountUtf8 => "count"u8;

    /// <summary><c>count</c> — the response page count of results in this page.</summary>
    public static readonly string Count = Utf8Constants.ToInternedString(CountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Total"/>.</summary>
    public static ReadOnlySpan<byte> TotalUtf8 => "total"u8;

    /// <summary><c>total</c> — the response page total of results matching the query.</summary>
    public static readonly string Total = Utf8Constants.ToInternedString(TotalUtf8);
}
