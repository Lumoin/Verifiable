using System.Diagnostics;

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
    /// <summary><c>subject</c> — the Subject entity of an Access Evaluation request.</summary>
    public static readonly string Subject = "subject";

    /// <summary><c>resource</c> — the Resource entity of an Access Evaluation request.</summary>
    public static readonly string Resource = "resource";

    /// <summary><c>action</c> — the Action entity of an Access Evaluation request.</summary>
    public static readonly string Action = "action";

    /// <summary><c>context</c> — the request Context object, or the per-decision response context.</summary>
    public static readonly string Context = "context";

    /// <summary><c>type</c> — the type of a Subject or Resource entity.</summary>
    public static readonly string Type = "type";

    /// <summary><c>id</c> — the identifier of a Subject or Resource entity.</summary>
    public static readonly string Id = "id";

    /// <summary><c>name</c> — the name of an Action entity.</summary>
    public static readonly string Name = "name";

    /// <summary><c>properties</c> — the free-form property bag of a Subject, Resource, or Action.</summary>
    public static readonly string Properties = "properties";

    /// <summary><c>decision</c> — the boolean Decision of an Access Evaluation response.</summary>
    public static readonly string Decision = "decision";

    /// <summary>
    /// <c>evaluations</c> — the array of per-item requests (Access Evaluations
    /// API request) or per-item decisions (response).
    /// </summary>
    public static readonly string Evaluations = "evaluations";

    /// <summary><c>options</c> — the options object of an Access Evaluations API request.</summary>
    public static readonly string Options = "options";

    /// <summary>
    /// <c>evaluations_semantic</c> — the batch evaluation semantic inside the
    /// <c>options</c> object. See <see cref="AuthZenEvaluationsSemanticValues"/>.
    /// </summary>
    public static readonly string EvaluationsSemantic = "evaluations_semantic";

    /// <summary><c>results</c> — the result array of a Search API response.</summary>
    public static readonly string Results = "results";

    /// <summary><c>page</c> — the pagination object of a Search API request or response.</summary>
    public static readonly string Page = "page";

    /// <summary><c>token</c> — the request page token (opaque continuation from a prior response).</summary>
    public static readonly string Token = "token";

    /// <summary><c>limit</c> — the request page size limit (maximum results).</summary>
    public static readonly string Limit = "limit";

    /// <summary><c>next_token</c> — the response page continuation token; empty string signals the end.</summary>
    public static readonly string NextToken = "next_token";

    /// <summary><c>count</c> — the response page count of results in this page.</summary>
    public static readonly string Count = "count";

    /// <summary><c>total</c> — the response page total of results matching the query.</summary>
    public static readonly string Total = "total";
}
