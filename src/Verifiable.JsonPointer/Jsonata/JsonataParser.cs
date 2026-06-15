using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Verifiable.JsonPointer.Jsonata;

/// <summary>
/// A small recursive-descent parser for the minimal in-repo JSONata subset: field / path
/// navigation, object construction, array construction, string concatenation, literals, and the
/// context (<c>$</c>) / a trivial variable (<c>$name</c>) reference. It is the parser the
/// <see cref="JsonataEvaluator"/> uses; the full JSONata grammar is parsed by the engine in
/// <c>Lumoin.Veritas</c> that supersedes this one in production.
/// </summary>
/// <remarks>
/// <para>
/// Any construct outside the subset — predicates <c>[pred]</c>, arithmetic, comparison / boolean
/// operators, conditionals <c>? :</c>, the <c>$</c>-function library, wildcards <c>*</c> / <c>**</c>,
/// higher-order functions, regex, lambdas, the transform / chain operators — is rejected with a
/// <see cref="JsonataUnsupportedFeatureException"/> as soon as it is recognized, so the evaluator
/// never silently mis-evaluates a template into a wrong credential. Text that is not valid JSONata at
/// all (an unterminated string, an unbalanced brace, a stray token, trailing text) is rejected with a
/// <see cref="JsonataParseException"/>.
/// </para>
/// <para>
/// <strong>Bounds:</strong> the source length is checked against
/// <see cref="JsonataLimits.MaxExpressionLength"/> before parsing, and brace / bracket nesting is
/// capped at <see cref="JsonataLimits.MaxParseDepth"/>, each tripping a
/// <see cref="JsonataEvaluationLimitException"/>, so a pathological source cannot over-allocate or
/// overflow the stack during parsing.
/// </para>
/// </remarks>
public static class JsonataParser
{
    /// <summary>
    /// Parses a template source into an abstract syntax tree the <see cref="JsonataEvaluator"/>
    /// walks.
    /// </summary>
    /// <param name="source">The template source text.</param>
    /// <returns>The parsed expression.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="source"/> is <c>null</c>.</exception>
    /// <exception cref="JsonataEvaluationLimitException">When the source exceeds a parse bound.</exception>
    /// <exception cref="JsonataUnsupportedFeatureException">When the source uses an out-of-scope construct.</exception>
    /// <exception cref="JsonataParseException">When the source is not well-formed JSONata of the supported subset.</exception>
    public static JsonataExpression Parse(string source)
    {
        ArgumentNullException.ThrowIfNull(source);

        if(source.Length > JsonataLimits.MaxExpressionLength)
        {
            throw new JsonataEvaluationLimitException(
                JsonataLimit.ExpressionLength,
                $"Template source length {source.Length} exceeds the maximum of {JsonataLimits.MaxExpressionLength} characters.");
        }

        var state = new ParseState(source);
        JsonataExpression expression = ParseExpression(state, depth: 0);
        state.SkipWhitespace();

        if(!state.IsAtEnd)
        {
            throw new JsonataParseException(
                $"Unexpected trailing text at position {state.Position}: '{state.Current}'.",
                state.Position);
        }

        return expression;
    }


    //Parses a full expression: a concatenation chain over primary expressions. Concatenation is the
    //only operator the subset implements; any other operator character is surfaced as unsupported.
    private static JsonataExpression ParseExpression(ParseState state, int depth)
    {
        GuardParseDepth(depth);

        JsonataExpression left = ParsePrimary(state, depth);
        state.SkipWhitespace();

        while(!state.IsAtEnd && state.Current == '&')
        {
            state.Advance();
            JsonataExpression right = ParsePrimary(state, depth);
            left = new JsonataConcatExpression(left, right);
            state.SkipWhitespace();
        }

        RejectUnsupportedOperator(state);

        return left;
    }


    //Parses one primary expression and any trailing dotted path / unsupported postfix.
    private static JsonataExpression ParsePrimary(ParseState state, int depth)
    {
        GuardParseDepth(depth);
        state.SkipWhitespace();

        if(state.IsAtEnd)
        {
            throw new JsonataParseException("Unexpected end of template source; expected an expression.", state.Position);
        }

        char c = state.Current;

        return c switch
        {
            '{' => ParseObject(state, depth),
            '[' => ParseArray(state, depth),
            '"' or '\'' => new JsonataLiteralExpression(JsonataValue.FromString(ParseStringLiteral(state))),
            '$' => ParseDollar(state),
            '(' => throw new JsonataUnsupportedFeatureException(
                "Parenthesized / block expressions are not supported by the minimal in-repo evaluator; wire the full engine."),
            '-' or (>= '0' and <= '9') => new JsonataLiteralExpression(ParseNumberLiteral(state)),
            _ => ParseNameOrKeyword(state)
        };
    }


    //Parses a bare name: a keyword literal (true/false/null) or the head of a dotted path. Trailing
    //path segments and any unsupported postfix (predicate, function call) are handled by the path
    //parser.
    private static JsonataExpression ParseNameOrKeyword(ParseState state)
    {
        int start = state.Position;
        string name = ReadName(state);

        if(name.Length == 0)
        {
            throw new JsonataParseException(
                $"Unexpected character at position {start}: '{state.Current}'.",
                start);
        }

        JsonataValue? keyword = name switch
        {
            "true" => JsonataValue.True,
            "false" => JsonataValue.False,
            "null" => JsonataValue.Null,
            _ => null
        };

        if(keyword is JsonataValue literal && !IsPathContinuation(state))
        {
            return new JsonataLiteralExpression(literal);
        }

        return ParsePathFromHead(state, name, isContextRooted: false);
    }


    //Parses a '$'-prefixed token: the bare context '$', or a '$name' variable reference, then any
    //trailing dotted path. A function call ('$fn(...)') is rejected as unsupported.
    private static JsonataExpression ParseDollar(ParseState state)
    {
        state.Advance();

        string name = ReadName(state);

        state.SkipWhitespace();
        if(!state.IsAtEnd && state.Current == '(')
        {
            throw new JsonataUnsupportedFeatureException(
                $"The JSONata function '${name}(...)' is not supported by the minimal in-repo evaluator; wire the full engine.");
        }

        if(name.Length == 0)
        {
            //A bare '$' is the context reference; allow a trailing dotted path rooted at it.
            return ParsePathFromHead(state, head: null, isContextRooted: true);
        }

        //'$name': a variable reference. A trailing dotted path off a variable is out of scope here;
        //the bare variable is what VCALM templates need.
        if(IsPathContinuation(state))
        {
            throw new JsonataUnsupportedFeatureException(
                $"Navigating a path off the variable '${name}' is not supported by the minimal in-repo evaluator; wire the full engine.");
        }

        return new JsonataVariableExpression(name);
    }


    //Builds a path expression from an already-read head name (or null for a context-rooted path),
    //consuming any trailing '.field' segments. A predicate '[...]' or function call after the path is
    //rejected as unsupported.
    private static JsonataPathExpression ParsePathFromHead(ParseState state, string? head, bool isContextRooted)
    {
        var steps = new List<string>();
        if(head is not null)
        {
            steps.Add(head);
        }

        while(true)
        {
            state.SkipWhitespace();
            if(state.IsAtEnd)
            {
                break;
            }

            char c = state.Current;
            if(c == '.')
            {
                state.Advance();
                state.SkipWhitespace();

                if(!state.IsAtEnd && (state.Current == '*' || state.Current == '('))
                {
                    throw new JsonataUnsupportedFeatureException(
                        "Wildcard / parenthesized path steps are not supported by the minimal in-repo evaluator; wire the full engine.");
                }

                string step = ReadPathStep(state);
                if(step.Length == 0)
                {
                    throw new JsonataParseException(
                        $"Expected a field name after '.' at position {state.Position}.",
                        state.Position);
                }

                steps.Add(step);

                continue;
            }

            if(c == '[')
            {
                throw new JsonataUnsupportedFeatureException(
                    "Predicates / index expressions '[...]' are not supported by the minimal in-repo evaluator; wire the full engine.");
            }

            if(c == '(')
            {
                throw new JsonataUnsupportedFeatureException(
                    "Function calls are not supported by the minimal in-repo evaluator; wire the full engine.");
            }

            break;
        }

        return new JsonataPathExpression(steps, isContextRooted);
    }


    private static JsonataObjectExpression ParseObject(ParseState state, int depth)
    {
        GuardParseDepth(depth + 1);

        state.Advance();
        var members = new List<KeyValuePair<string, JsonataExpression>>();

        state.SkipWhitespace();
        if(!state.IsAtEnd && state.Current == '}')
        {
            state.Advance();

            return new JsonataObjectExpression(members);
        }

        while(true)
        {
            state.SkipWhitespace();
            if(state.IsAtEnd)
            {
                throw new JsonataParseException("Unterminated object; expected '}'.", state.Position);
            }

            if(state.Current is not ('"' or '\''))
            {
                throw new JsonataUnsupportedFeatureException(
                    "Computed / non-string object keys are not supported by the minimal in-repo evaluator; wire the full engine.");
            }

            string key = ParseStringLiteral(state);

            state.SkipWhitespace();
            if(state.IsAtEnd || state.Current != ':')
            {
                throw new JsonataParseException(
                    $"Expected ':' after object key '{key}' at position {state.Position}.",
                    state.Position);
            }

            state.Advance();
            JsonataExpression value = ParseExpression(state, depth + 1);
            members.Add(new KeyValuePair<string, JsonataExpression>(key, value));

            state.SkipWhitespace();
            if(state.IsAtEnd)
            {
                throw new JsonataParseException("Unterminated object; expected ',' or '}'.", state.Position);
            }

            if(state.Current == ',')
            {
                state.Advance();

                continue;
            }

            if(state.Current == '}')
            {
                state.Advance();

                return new JsonataObjectExpression(members);
            }

            throw new JsonataParseException(
                $"Expected ',' or '}}' in object at position {state.Position}; found '{state.Current}'.",
                state.Position);
        }
    }


    private static JsonataArrayExpression ParseArray(ParseState state, int depth)
    {
        GuardParseDepth(depth + 1);

        state.Advance();
        var elements = new List<JsonataExpression>();

        state.SkipWhitespace();
        if(!state.IsAtEnd && state.Current == ']')
        {
            state.Advance();

            return new JsonataArrayExpression(elements);
        }

        while(true)
        {
            JsonataExpression element = ParseExpression(state, depth + 1);
            elements.Add(element);

            state.SkipWhitespace();
            if(state.IsAtEnd)
            {
                throw new JsonataParseException("Unterminated array; expected ',' or ']'.", state.Position);
            }

            if(state.Current == ',')
            {
                state.Advance();

                continue;
            }

            if(state.Current == ']')
            {
                state.Advance();

                return new JsonataArrayExpression(elements);
            }

            throw new JsonataParseException(
                $"Expected ',' or ']' in array at position {state.Position}; found '{state.Current}'.",
                state.Position);
        }
    }


    //Reads a single- or double-quoted JSON string literal, honoring backslash escapes. JSONata
    //accepts both quote styles; VCALM Appendix-D templates use both.
    private static string ParseStringLiteral(ParseState state)
    {
        char quote = state.Current;
        int start = state.Position;
        state.Advance();

        var builder = new StringBuilder();

        while(true)
        {
            if(state.IsAtEnd)
            {
                throw new JsonataParseException($"Unterminated string literal starting at position {start}.", start);
            }

            char c = state.Current;
            if(c == quote)
            {
                state.Advance();

                return builder.ToString();
            }

            if(c == '\\')
            {
                state.Advance();
                if(state.IsAtEnd)
                {
                    throw new JsonataParseException($"Unterminated escape in string literal at position {state.Position}.", state.Position);
                }

                char escape = state.Current;
                builder.Append(escape switch
                {
                    '"' => '"',
                    '\'' => '\'',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\b',
                    'f' => '\f',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => ReadUnicodeEscape(state),
                    _ => throw new JsonataParseException($"Invalid escape '\\{escape}' at position {state.Position}.", state.Position)
                });

                state.Advance();

                continue;
            }

            builder.Append(c);
            state.Advance();
        }
    }


    private static char ReadUnicodeEscape(ParseState state)
    {
        //state.Current is 'u'; the four hex digits follow.
        if(state.Position + 4 >= state.Length)
        {
            throw new JsonataParseException($"Truncated '\\u' escape at position {state.Position}.", state.Position);
        }

        ReadOnlySpan<char> hex = state.Source.AsSpan(state.Position + 1, 4);
        if(!ushort.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ushort code))
        {
            throw new JsonataParseException($"Invalid '\\u' escape at position {state.Position}.", state.Position);
        }

        state.Advance(4);

        return (char)code;
    }


    private static JsonataValue ParseNumberLiteral(ParseState state)
    {
        int start = state.Position;
        if(state.Current == '-')
        {
            state.Advance();
        }

        bool isFractional = false;
        while(!state.IsAtEnd)
        {
            char c = state.Current;
            if(c is >= '0' and <= '9')
            {
                state.Advance();

                continue;
            }

            if(c is '.' or 'e' or 'E' or '+' or '-')
            {
                isFractional = isFractional || c is '.' or 'e' or 'E';
                state.Advance();

                continue;
            }

            break;
        }

        ReadOnlySpan<char> token = state.Source.AsSpan(start, state.Position - start);
        if(!isFractional && long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out long integral))
        {
            return JsonataValue.FromInteger(integral);
        }

        if(double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out double fractional))
        {
            return JsonataValue.FromNumber(fractional);
        }

        throw new JsonataParseException($"Invalid number literal '{token.ToString()}' at position {start}.", start);
    }


    //Reads a JSONata name token (the head of a path or a keyword): a letter or underscore followed by
    //letters, digits, or underscores.
    private static string ReadName(ParseState state)
    {
        int start = state.Position;
        if(state.IsAtEnd)
        {
            return string.Empty;
        }

        char first = state.Current;
        if(!IsNameStart(first))
        {
            return string.Empty;
        }

        state.Advance();
        while(!state.IsAtEnd && IsNamePart(state.Current))
        {
            state.Advance();
        }

        return state.Source[start..state.Position];
    }


    //Reads one path step, which is a backtick-quoted name (JSONata's quoted field syntax) or a plain
    //name.
    private static string ReadPathStep(ParseState state)
    {
        if(!state.IsAtEnd && state.Current == '`')
        {
            int start = state.Position;
            state.Advance();
            var builder = new StringBuilder();
            while(true)
            {
                if(state.IsAtEnd)
                {
                    throw new JsonataParseException($"Unterminated backtick-quoted field starting at position {start}.", start);
                }

                if(state.Current == '`')
                {
                    state.Advance();

                    return builder.ToString();
                }

                builder.Append(state.Current);
                state.Advance();
            }
        }

        return ReadName(state);
    }


    //Whether the next non-whitespace character begins a dotted path continuation off a name.
    private static bool IsPathContinuation(ParseState state)
    {
        int saved = state.Position;
        state.SkipWhitespace();
        bool isContinuation = !state.IsAtEnd && (state.Current == '.' || state.Current == '[' || state.Current == '(');
        state.Position = saved;

        return isContinuation;
    }


    //Rejects an operator character that is recognized JSONata but outside the supported subset, so a
    //template using arithmetic / comparison / conditional / chain operators errors rather than being
    //silently truncated to its left operand.
    private static void RejectUnsupportedOperator(ParseState state)
    {
        if(state.IsAtEnd)
        {
            return;
        }

        char c = state.Current;
        bool isUnsupportedOperator = c is '+' or '*' or '/' or '%' or '=' or '<' or '>' or '!' or '?' or ':' or '~' or '|';

        //'-' is only an operator here (number literals are consumed by the primary parser); a bare
        //'-' after an expression is subtraction, which is out of scope.
        isUnsupportedOperator = isUnsupportedOperator || c == '-';

        if(isUnsupportedOperator)
        {
            throw new JsonataUnsupportedFeatureException(
                $"The operator '{c}' is not supported by the minimal in-repo evaluator; wire the full engine.");
        }
    }


    private static void GuardParseDepth(int depth)
    {
        if(depth > JsonataLimits.MaxParseDepth)
        {
            throw new JsonataEvaluationLimitException(
                JsonataLimit.ParseDepth,
                $"Template nesting depth exceeds the maximum of {JsonataLimits.MaxParseDepth}.");
        }
    }


    private static bool IsNameStart(char c) => char.IsAsciiLetter(c) || c == '_';

    private static bool IsNamePart(char c) => char.IsAsciiLetterOrDigit(c) || c == '_';


    //The mutable cursor over the template source.
    private sealed class ParseState
    {
        public ParseState(string source)
        {
            Source = source;
        }


        public string Source { get; }

        public int Length => Source.Length;

        public int Position { get; set; }

        public bool IsAtEnd => Position >= Source.Length;

        public char Current => Source[Position];


        public void Advance(int count = 1)
        {
            Position += count;
        }


        public void SkipWhitespace()
        {
            while(Position < Source.Length && char.IsWhiteSpace(Source[Position]))
            {
                Position++;
            }
        }
    }
}
