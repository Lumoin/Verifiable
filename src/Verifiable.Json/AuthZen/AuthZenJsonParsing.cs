using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth.AuthZen;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> implementations of the OpenID AuthZEN
/// Authorization API 1.0 request parsers — the JSON side that the
/// <c>Verifiable.OAuth</c> serialization firewall keeps out of the core
/// library. Wire these onto an
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration"/> with
/// <see cref="AuthZenJsonExtensions.UseDefaultAuthZenJsonParsing"/>.
/// </summary>
/// <remarks>
/// <para>
/// The parsers are STRICT (per the strict-conformance principle): a body that
/// is not a JSON object, is missing a required field, carries a field of the
/// wrong JSON type, or names an unrecognised <c>evaluations_semantic</c>
/// yields <see langword="null"/> — the endpoint then responds HTTP 400. They
/// never throw to the caller.
/// </para>
/// <para>
/// The free-form <c>properties</c> / <c>context</c> objects are materialised
/// into <see cref="IReadOnlyDictionary{TKey,TValue}"/> via
/// <see cref="JsonElementConversion"/>; the library treats them opaquely.
/// </para>
/// </remarks>
public static class AuthZenJsonParsing
{
    /// <summary>
    /// Parses an Access Evaluation request (§4). <c>subject</c>, <c>action</c>,
    /// and <c>resource</c> are required; <c>context</c> is optional.
    /// </summary>
    public static ValueTask<AccessEvaluationRequest?> ParseAccessEvaluationRequest(
        string requestBody, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        try
        {
            using JsonDocument doc = JsonDocument.Parse(requestBody);
            JsonElement root = RequireObject(doc.RootElement);

            AuthZenSubject? subject = ReadSubject(root, idOptional: false);
            AuthZenAction? action = ReadAction(root);
            AuthZenResource? resource = ReadResource(root, idOptional: false);
            if(subject is null || action is null || resource is null)
            {
                return Null<AccessEvaluationRequest>();
            }

            return ValueTask.FromResult<AccessEvaluationRequest?>(new AccessEvaluationRequest
            {
                Subject = subject,
                Action = action,
                Resource = resource,
                Context = ReadObjectField(root, AuthZenFieldNames.Context),
            });
        }
        catch(Exception ex) when(IsParseFailure(ex))
        {
            return Null<AccessEvaluationRequest>();
        }
    }


    /// <summary>
    /// Parses an Access Evaluations (batch) request (§6): request-level
    /// defaults, an <c>evaluations</c> array of per-item overrides, and
    /// optional <c>options.evaluations_semantic</c>.
    /// </summary>
    public static ValueTask<AccessEvaluationsRequest?> ParseAccessEvaluationsRequest(
        string requestBody, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        try
        {
            using JsonDocument doc = JsonDocument.Parse(requestBody);
            JsonElement root = RequireObject(doc.RootElement);

            List<AccessEvaluationItem> items = [];
            if(root.TryGetProperty(AuthZenFieldNames.Evaluations, out JsonElement evaluations))
            {
                if(evaluations.ValueKind != JsonValueKind.Array)
                {
                    return Null<AccessEvaluationsRequest>();
                }

                foreach(JsonElement entry in evaluations.EnumerateArray())
                {
                    JsonElement item = RequireObject(entry);
                    items.Add(new AccessEvaluationItem
                    {
                        Subject = ReadSubject(item, idOptional: false),
                        Action = ReadAction(item),
                        Resource = ReadResource(item, idOptional: false),
                        Context = ReadObjectField(item, AuthZenFieldNames.Context),
                    });
                }
            }

            AccessEvaluationsOptions? options = null;
            if(root.TryGetProperty(AuthZenFieldNames.Options, out JsonElement opts))
            {
                JsonElement optionsObject = RequireObject(opts);
                if(optionsObject.TryGetProperty(AuthZenFieldNames.EvaluationsSemantic, out JsonElement semanticElement))
                {
                    if(!AuthZenEvaluationsSemanticValues.TryParse(
                            semanticElement.GetString(), out AuthZenEvaluationsSemantic semantic))
                    {
                        //Strict: an unrecognised semantic is not a valid request.
                        return Null<AccessEvaluationsRequest>();
                    }

                    options = new AccessEvaluationsOptions { Semantic = semantic };
                }
            }

            return ValueTask.FromResult<AccessEvaluationsRequest?>(new AccessEvaluationsRequest
            {
                Subject = ReadSubject(root, idOptional: false),
                Action = ReadAction(root),
                Resource = ReadResource(root, idOptional: false),
                Context = ReadObjectField(root, AuthZenFieldNames.Context),
                Evaluations = items,
                Options = options,
            });
        }
        catch(Exception ex) when(IsParseFailure(ex))
        {
            return Null<AccessEvaluationsRequest>();
        }
    }


    /// <summary>
    /// Parses a Search API request (§7) — one shape for all three endpoints.
    /// The searched dimension's <c>id</c> is optional (the spec omits and
    /// ignores it); the opaque <c>page</c> cursor is carried through.
    /// </summary>
    public static ValueTask<AccessSearchRequest?> ParseAccessSearchRequest(
        string requestBody, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        try
        {
            using JsonDocument doc = JsonDocument.Parse(requestBody);
            JsonElement root = RequireObject(doc.RootElement);

            AccessSearchPageRequest? page = null;
            if(root.TryGetProperty(AuthZenFieldNames.Page, out JsonElement pageElement))
            {
                JsonElement pageObject = RequireObject(pageElement);
                page = new AccessSearchPageRequest
                {
                    Token = pageObject.TryGetProperty(AuthZenFieldNames.Token, out JsonElement t)
                        ? t.GetString()
                        : null,
                    Limit = pageObject.TryGetProperty(AuthZenFieldNames.Limit, out JsonElement l)
                        ? l.GetInt32()
                        : null,
                    Properties = ReadObjectField(pageObject, AuthZenFieldNames.Properties),
                };
            }

            //§7: the searched dimension carries only its type — id is optional.
            return ValueTask.FromResult<AccessSearchRequest?>(new AccessSearchRequest
            {
                Subject = ReadSubject(root, idOptional: true),
                Action = ReadAction(root),
                Resource = ReadResource(root, idOptional: true),
                Context = ReadObjectField(root, AuthZenFieldNames.Context),
                Page = page,
            });
        }
        catch(Exception ex) when(IsParseFailure(ex))
        {
            return Null<AccessSearchRequest>();
        }
    }


    //Helpers below the public surface.

    private static AuthZenSubject? ReadSubject(JsonElement parent, bool idOptional)
    {
        if(!parent.TryGetProperty(AuthZenFieldNames.Subject, out JsonElement s))
        {
            return null;
        }

        JsonElement entity = RequireObject(s);
        return new AuthZenSubject
        {
            Type = RequireString(entity, AuthZenFieldNames.Type),
            Id = ReadId(entity, idOptional),
            Properties = ReadObjectField(entity, AuthZenFieldNames.Properties),
        };
    }


    private static AuthZenResource? ReadResource(JsonElement parent, bool idOptional)
    {
        if(!parent.TryGetProperty(AuthZenFieldNames.Resource, out JsonElement r))
        {
            return null;
        }

        JsonElement entity = RequireObject(r);
        return new AuthZenResource
        {
            Type = RequireString(entity, AuthZenFieldNames.Type),
            Id = ReadId(entity, idOptional),
            Properties = ReadObjectField(entity, AuthZenFieldNames.Properties),
        };
    }


    private static AuthZenAction? ReadAction(JsonElement parent)
    {
        if(!parent.TryGetProperty(AuthZenFieldNames.Action, out JsonElement a))
        {
            return null;
        }

        JsonElement entity = RequireObject(a);
        return new AuthZenAction
        {
            Name = RequireString(entity, AuthZenFieldNames.Name),
            Properties = ReadObjectField(entity, AuthZenFieldNames.Properties),
        };
    }


    /// <summary>
    /// Reads the entity <c>id</c>: required (a non-empty string) unless
    /// <paramref name="idOptional"/>, in which case an absent id maps to the
    /// empty string (the §7 search dimension carries only its type).
    /// </summary>
    private static string ReadId(JsonElement entity, bool idOptional)
    {
        if(entity.TryGetProperty(AuthZenFieldNames.Id, out JsonElement id))
        {
            return id.GetString() ?? throw new JsonException("id must be a string.");
        }

        if(idOptional)
        {
            return "";
        }

        throw new JsonException("Required field 'id' is missing.");
    }


    private static string RequireString(JsonElement entity, string field)
    {
        if(!entity.TryGetProperty(field, out JsonElement value))
        {
            throw new JsonException($"Required field '{field}' is missing.");
        }

        return value.GetString() ?? throw new JsonException($"Field '{field}' must be a string.");
    }


    /// <summary>
    /// Reads an optional object-valued field into an opaque dictionary, or
    /// <see langword="null"/> when absent. A present non-object value is a
    /// strict parse failure.
    /// </summary>
    private static IReadOnlyDictionary<string, object>? ReadObjectField(JsonElement parent, string field)
    {
        if(!parent.TryGetProperty(field, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"Field '{field}' must be a JSON object.");
        }

        return (Dictionary<string, object>)JsonElementConversion.Convert(value)!;
    }


    private static JsonElement RequireObject(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Expected a JSON object.");
        }

        return element;
    }


    private static bool IsParseFailure(Exception ex) =>
        ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or NotSupportedException;


    private static ValueTask<T?> Null<T>() where T : class => ValueTask.FromResult<T?>(null);
}
