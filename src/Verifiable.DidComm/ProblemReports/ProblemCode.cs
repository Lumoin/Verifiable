using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.DidComm.ProblemReports;

/// <summary>
/// A parsed DIDComm problem code — the <c>code</c> field of a problem report that categorizes what went
/// wrong, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#problem-codes">DIDComm Messaging v2.1 §Problem Codes</see>.
/// </summary>
/// <remarks>
/// <para>
/// A problem code is a sequence of lower kebab-case tokens delimited by <c>.</c>, ordered general to
/// specific left to right: a <see cref="Sorter"/> (the single character <c>e</c> or <c>w</c>), then a
/// <see cref="Scope"/> token, then zero or more <see cref="Descriptors"/>. Recipients can match by prefix
/// rather than full string, so a handler can recognize broad semantics even when trailing tokens are
/// unfamiliar — <see cref="StartsWith(string)"/> implements that token-wise prefix match
/// (DIDComm v2.1 §Problem Codes).
/// </para>
/// <para>
/// This type models the code STRUCTURE for dispatch; it does not enumerate every descriptor. The defined
/// descriptor tokens (<c>trust</c>, <c>xfer</c>, <c>did</c>, <c>msg</c>, <c>me</c>, <c>req</c>, <c>legal</c>,
/// and their sub-descriptors) are open — individual protocols define more (DIDComm v2.1 §Descriptors) —
/// and are surfaced as reuse constants in <see cref="WellKnownProblemCodes"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ProblemCode({Value})")]
public sealed class ProblemCode: IEquatable<ProblemCode>
{
    //A problem code is a short dotted token sequence (sorter.scope.descriptor...); an attacker-supplied value
    //is length-bounded before Split so it cannot drive a large token-array allocation (DIDComm v2.1 §Problem
    //Codes — codes are compact identifiers, not free text).
    private const int MaximumLength = 256;

    private readonly string[] tokens;


    private ProblemCode(string value, string[] tokens, ProblemSorter sorter)
    {
        Value = value;
        this.tokens = tokens;
        Sorter = sorter;
    }


    /// <summary>The full problem code string exactly as supplied, e.g. <c>e.p.xfer.cant-use-endpoint</c>.</summary>
    public string Value { get; }

    /// <summary>The sorter — the leftmost token mapped to <see cref="ProblemSorter.Error"/> (<c>e</c>) or <see cref="ProblemSorter.Warning"/> (<c>w</c>).</summary>
    public ProblemSorter Sorter { get; }

    /// <summary>Whether the sorter is <see cref="ProblemSorter.Error"/> (<c>e</c>).</summary>
    public bool IsError => Sorter == ProblemSorter.Error;

    /// <summary>Whether the sorter is <see cref="ProblemSorter.Warning"/> (<c>w</c>).</summary>
    public bool IsWarning => Sorter == ProblemSorter.Warning;

    /// <summary>The <c>e</c> sorter token — the leftmost token of an error code (DIDComm v2.1 §Sorter).</summary>
    public static string ErrorToken => "e";

    /// <summary>The <c>w</c> sorter token — the leftmost token of a warning code (DIDComm v2.1 §Sorter).</summary>
    public static string WarningToken => "w";

    /// <summary>
    /// The scope — the second token, the sender's opinion of how much context should be undone if the
    /// problem is an error: <c>p</c> (the whole protocol), <c>m</c> (the previous message only), or a
    /// formal state name from the sender's state machine (DIDComm v2.1 §Scope).
    /// </summary>
    public string Scope => tokens[1];

    /// <summary>The descriptor tokens — every token after the sorter and scope, progressively more specific (DIDComm v2.1 §Descriptors). May be empty.</summary>
    public IReadOnlyList<string> Descriptors => tokens.Length > 2 ? tokens[2..] : [];

    /// <summary>All tokens of the code, in order: sorter, scope, then descriptors.</summary>
    public IReadOnlyList<string> Tokens => Array.AsReadOnly(tokens);


    /// <summary>
    /// Parses <paramref name="value"/> as a problem code.
    /// </summary>
    /// <param name="value">The problem code string.</param>
    /// <param name="result">The parsed code when parsing succeeds.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="value"/> is a well-formed problem code: a non-empty
    /// dot-delimited sequence of at least a sorter and a scope, every token lower kebab-case, the sorter
    /// exactly <c>e</c> or <c>w</c> (DIDComm v2.1 §Problem Codes).
    /// </returns>
    public static bool TryParse([NotNullWhen(true)] string? value, [NotNullWhen(true)] out ProblemCode? result)
    {
        result = null;
        if(string.IsNullOrEmpty(value) || value.Length > MaximumLength)
        {
            return false;
        }

        string[] tokens = value.Split('.');

        //A code MUST carry at least a sorter and a scope (DIDComm v2.1 §Problem Codes / §Scope). A
        //descriptor is a SHOULD, so a two-token code such as "e.p" parses.
        if(tokens.Length < 2)
        {
            return false;
        }

        foreach(string token in tokens)
        {
            if(!IsLowerKebabToken(token))
            {
                return false;
            }
        }

        //The sorter is a single character; exactly "e" or "w" are defined (DIDComm v2.1 §Sorter).
        ProblemSorter sorter;
        if(string.Equals(tokens[0], ErrorToken, StringComparison.Ordinal))
        {
            sorter = ProblemSorter.Error;
        }
        else if(string.Equals(tokens[0], WarningToken, StringComparison.Ordinal))
        {
            sorter = ProblemSorter.Warning;
        }
        else
        {
            return false;
        }

        result = new ProblemCode(value, tokens, sorter);

        return true;
    }


    /// <summary>
    /// Parses <paramref name="value"/> as a problem code, throwing when it is not well-formed.
    /// </summary>
    /// <param name="value">The problem code string.</param>
    /// <returns>The parsed code.</returns>
    /// <exception cref="FormatException">Thrown when <paramref name="value"/> is not a well-formed problem code.</exception>
    public static ProblemCode Parse(string value)
    {
        if(!TryParse(value, out ProblemCode? result))
        {
            throw new FormatException(
                $"'{value}' is not a well-formed DIDComm problem code " +
                "(expected lower kebab-case <sorter:e|w>.<scope>[.<descriptor>…]) (DIDComm v2.1 §Problem Codes).");
        }

        return result;
    }


    /// <summary>
    /// Whether this code begins with <paramref name="prefix"/> on a token boundary — the token-wise prefix
    /// match recipients use to recognize broad semantics even when trailing tokens are unfamiliar
    /// (DIDComm v2.1 §Problem Codes). Matching is by whole token, not by substring: <c>e.p.xfer.x</c> does
    /// NOT start with <c>e.p.x</c>.
    /// </summary>
    /// <param name="prefix">The dot-delimited token prefix, e.g. <c>e.p.xfer</c>.</param>
    /// <returns><see langword="true"/> when every token of <paramref name="prefix"/> equals the code's token at the same position.</returns>
    public bool StartsWith(string prefix)
    {
        if(string.IsNullOrEmpty(prefix))
        {
            return false;
        }

        string[] prefixTokens = prefix.Split('.');
        if(prefixTokens.Length > tokens.Length)
        {
            return false;
        }

        for(int i = 0; i < prefixTokens.Length; ++i)
        {
            //An empty prefix token (e.g. a trailing dot) cannot match a non-empty code token.
            if(!string.Equals(prefixTokens[i], tokens[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }


    //A lower kebab-case token: at least one character drawn from [a-z0-9-], starting and ending with an
    //alphanumeric so a token cannot be (or begin/end with) a bare separator (DIDComm v2.1 §Problem Codes:
    //"lower kebab-case"). Rejecting uppercase keeps the case-significant comparison meaningful. Interior
    //hyphens are accepted liberally — the spec names no grammar beyond "lower kebab-case", so the receiver
    //does not fail an otherwise-recoverable code closed over an interior detail it does not constrain.
    private static bool IsLowerKebabToken(string token)
    {
        if(token.Length == 0 || token[0] == '-' || token[^1] == '-')
        {
            return false;
        }

        foreach(char c in token)
        {
            bool isAllowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
            if(!isAllowed)
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ProblemCode? other) =>
        other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is ProblemCode other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Value.GetHashCode(StringComparison.Ordinal);

    /// <inheritdoc/>
    public override string ToString() => Value;
}
