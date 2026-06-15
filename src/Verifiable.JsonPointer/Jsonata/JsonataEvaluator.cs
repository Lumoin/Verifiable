using System.Collections.Generic;
using System.Globalization;

namespace Verifiable.JsonPointer.Jsonata;

/// <summary>
/// The minimal in-repo JSONata evaluator: it parses a template source and evaluates it against an
/// input value (the exchange variables) into an output value (the credential body). It implements
/// only the in-scope subset — field / path navigation, object construction, array construction,
/// string concatenation, literals, and the context (<c>$</c>) / a trivial variable (<c>$name</c>)
/// reference — which is just enough to make the VCALM §3.6 <c>credentialTemplates</c> feature
/// function. The full JSONata engine from <c>Lumoin.Veritas</c> supersedes this evaluator as the
/// production engine; a deployment registers it at the VCALM template-evaluation seam.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Purity:</strong> evaluation is pure and deterministic — no I/O, no clock, no randomness,
/// no environment, no reflection, no static mutable state. The same template and input always
/// produce the same output. This matters because the output becomes an issued credential.
/// </para>
/// <para>
/// <strong>Bounds:</strong> recursive descent is capped at
/// <see cref="JsonataLimits.MaxEvaluationDepth"/> and the total number of evaluated nodes at
/// <see cref="JsonataLimits.MaxEvaluationSteps"/>, each tripping a
/// <see cref="JsonataEvaluationLimitException"/>, so a pathological template or input cannot hang,
/// overflow the stack, or over-allocate.
/// </para>
/// </remarks>
public static class JsonataEvaluator
{
    /// <summary>
    /// Parses <paramref name="templateSource"/> and evaluates it against <paramref name="input"/>,
    /// returning the produced value. <paramref name="input"/> is both the implicit evaluation
    /// context (a bare path navigates into it) and the source of named variables (a member of an
    /// input object is reachable as <c>$member</c>). This is the one-shot convenience over
    /// <see cref="JsonataParser.Parse"/> + <see cref="Evaluate(JsonataExpression, JsonataValue)"/>.
    /// </summary>
    /// <param name="templateSource">The JSONata template source text.</param>
    /// <param name="input">The input value (the exchange variables).</param>
    /// <returns>The produced value (the credential body).</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="templateSource"/> is <c>null</c>.</exception>
    /// <exception cref="JsonataEvaluationLimitException">When a parse or evaluation bound is exceeded.</exception>
    /// <exception cref="JsonataUnsupportedFeatureException">When the template uses an out-of-scope construct.</exception>
    /// <exception cref="JsonataParseException">When the template is malformed.</exception>
    public static JsonataValue Evaluate(string templateSource, JsonataValue input)
    {
        ArgumentNullException.ThrowIfNull(templateSource);

        JsonataExpression expression = JsonataParser.Parse(templateSource);

        return Evaluate(expression, input);
    }


    /// <summary>
    /// Evaluates an already-parsed <paramref name="expression"/> against <paramref name="input"/>,
    /// returning the produced value.
    /// </summary>
    /// <param name="expression">The parsed expression.</param>
    /// <param name="input">The input value (the exchange variables).</param>
    /// <returns>The produced value (the credential body).</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="expression"/> is <c>null</c>.</exception>
    /// <exception cref="JsonataEvaluationLimitException">When an evaluation bound is exceeded.</exception>
    public static JsonataValue Evaluate(JsonataExpression expression, JsonataValue input)
    {
        ArgumentNullException.ThrowIfNull(expression);

        var budget = new EvaluationBudget();

        return EvaluateNode(expression, input, depth: 0, budget);
    }


    private static JsonataValue EvaluateNode(JsonataExpression expression, JsonataValue context, int depth, EvaluationBudget budget)
    {
        if(depth > JsonataLimits.MaxEvaluationDepth)
        {
            throw new JsonataEvaluationLimitException(
                JsonataLimit.EvaluationDepth,
                $"Evaluation depth exceeds the maximum of {JsonataLimits.MaxEvaluationDepth}.");
        }

        budget.Step();

        return expression switch
        {
            JsonataLiteralExpression literal => literal.Value,
            JsonataPathExpression path => EvaluatePath(path, context),
            JsonataVariableExpression variable => context.GetMemberOrNull(variable.Name),
            JsonataObjectExpression obj => EvaluateObject(obj, context, depth, budget),
            JsonataArrayExpression array => EvaluateArray(array, context, depth, budget),
            JsonataConcatExpression concat => EvaluateConcat(concat, context, depth, budget),
            _ => throw new JsonataUnsupportedFeatureException(
                $"The expression node '{expression.GetType().Name}' is not supported by the minimal in-repo evaluator; wire the full engine.")
        };
    }


    private static JsonataValue EvaluatePath(JsonataPathExpression path, JsonataValue context)
    {
        JsonataValue current = context;
        foreach(string step in path.Steps)
        {
            current = current.GetMemberOrNull(step);
            if(current.IsNull)
            {
                return JsonataValue.Null;
            }
        }

        return current;
    }


    private static JsonataValue EvaluateObject(JsonataObjectExpression obj, JsonataValue context, int depth, EvaluationBudget budget)
    {
        var members = new Dictionary<string, JsonataValue>(obj.Members.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, JsonataExpression> member in obj.Members)
        {
            JsonataValue value = EvaluateNode(member.Value, context, depth + 1, budget);

            //A member whose value navigates to nothing is omitted, matching JSONata: constructing an
            //object member from an absent path yields no member rather than a JSON null.
            if(value.IsNull)
            {
                continue;
            }

            members[member.Key] = value;
        }

        return JsonataValue.FromObject(members);
    }


    private static JsonataValue EvaluateArray(JsonataArrayExpression array, JsonataValue context, int depth, EvaluationBudget budget)
    {
        var elements = new List<JsonataValue>(array.Elements.Count);
        foreach(JsonataExpression element in array.Elements)
        {
            elements.Add(EvaluateNode(element, context, depth + 1, budget));
        }

        return JsonataValue.FromArray(elements);
    }


    private static JsonataValue EvaluateConcat(JsonataConcatExpression concat, JsonataValue context, int depth, EvaluationBudget budget)
    {
        JsonataValue left = EvaluateNode(concat.Left, context, depth + 1, budget);
        JsonataValue right = EvaluateNode(concat.Right, context, depth + 1, budget);

        return JsonataValue.FromString(Stringify(left) + Stringify(right));
    }


    //Renders a value to its string form for concatenation. JSONata's '&' coerces each operand to a
    //string; an absent (null) operand contributes the empty string.
    private static string Stringify(JsonataValue value)
    {
        return value.Kind switch
        {
            JsonataValueKind.Null => string.Empty,
            JsonataValueKind.String => value.AsString(),
            JsonataValueKind.Integer => value.AsInteger().ToString(CultureInfo.InvariantCulture),
            JsonataValueKind.Number => value.AsNumber().ToString("R", CultureInfo.InvariantCulture),
            JsonataValueKind.Boolean => value.AsBoolean() ? "true" : "false",
            _ => throw new JsonataUnsupportedFeatureException(
                "Concatenating an object or array operand is not supported by the minimal in-repo evaluator; wire the full engine.")
        };
    }


    //Tracks the evaluation step budget, tripping the step-count limit so a broad-but-shallow template
    //that never reaches the depth limit is still bounded.
    private sealed class EvaluationBudget
    {
        private int _steps;


        public void Step()
        {
            _steps++;
            if(_steps > JsonataLimits.MaxEvaluationSteps)
            {
                throw new JsonataEvaluationLimitException(
                    JsonataLimit.EvaluationSteps,
                    $"Evaluation step count exceeds the maximum of {JsonataLimits.MaxEvaluationSteps}.");
            }
        }
    }
}
