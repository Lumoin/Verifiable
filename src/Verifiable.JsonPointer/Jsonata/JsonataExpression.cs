using System.Collections.Generic;

namespace Verifiable.JsonPointer.Jsonata;

/// <summary>
/// One node in the abstract syntax tree the minimal in-repo JSONata parser produces and the
/// evaluator walks. The node set covers only the in-scope constructs — field / path navigation,
/// object construction, array construction, string concatenation, literals, and the context / a
/// trivial variable reference. Every other JSONata construct is rejected at parse time with a
/// <see cref="JsonataUnsupportedFeatureException"/> rather than represented here, so a wrong
/// credential is never constructed from an unsupported template.
/// </summary>
public abstract class JsonataExpression
{
    private protected JsonataExpression()
    {
    }
}


/// <summary>
/// A literal value baked into the template source: a string, number, boolean, or <c>null</c>. The
/// value is precomputed at parse time and yielded verbatim at evaluation time.
/// </summary>
public sealed class JsonataLiteralExpression: JsonataExpression
{
    /// <summary>
    /// The literal value.
    /// </summary>
    public JsonataValue Value { get; }


    /// <summary>
    /// Creates a literal expression.
    /// </summary>
    /// <param name="value">The literal value.</param>
    public JsonataLiteralExpression(JsonataValue value)
    {
        Value = value;
    }
}


/// <summary>
/// A path navigation: a dotted sequence of field names (<c>foo</c>, <c>foo.bar.baz</c>) navigated
/// from the value the path is rooted at. The first step is rooted either at the evaluation context
/// (a bare path such as <c>sampleAchievementCredential.id</c>) or at the explicit context reference
/// <c>$</c> when <see cref="IsContextRooted"/> is set. A step into an absent member yields
/// <see cref="JsonataValue.Null"/> (JSONata navigation of nothing is nothing).
/// </summary>
public sealed class JsonataPathExpression: JsonataExpression
{
    /// <summary>
    /// The field names to navigate, in order. At least one for a bare path; may be empty only when
    /// <see cref="IsContextRooted"/> is set, which then denotes the context value itself (<c>$</c>).
    /// </summary>
    public IReadOnlyList<string> Steps { get; }

    /// <summary>
    /// Whether the path is rooted at the explicit context reference <c>$</c> rather than at the
    /// implicit evaluation context.
    /// </summary>
    public bool IsContextRooted { get; }


    /// <summary>
    /// Creates a path expression.
    /// </summary>
    /// <param name="steps">The field names to navigate, in order.</param>
    /// <param name="isContextRooted">Whether the path is rooted at the explicit context reference <c>$</c>.</param>
    public JsonataPathExpression(IReadOnlyList<string> steps, bool isContextRooted)
    {
        Steps = steps;
        IsContextRooted = isContextRooted;
    }
}


/// <summary>
/// A reference to a named variable bound in the evaluation environment (<c>$name</c>). VCALM
/// templates carry their exchange variables as members of the context object, so a bare path is the
/// common case; this node covers the trivial <c>$name</c> spelling that resolves the same variable
/// by name from the environment.
/// </summary>
public sealed class JsonataVariableExpression: JsonataExpression
{
    /// <summary>
    /// The variable name, without the leading <c>$</c>.
    /// </summary>
    public string Name { get; }


    /// <summary>
    /// Creates a variable reference expression.
    /// </summary>
    /// <param name="name">The variable name, without the leading <c>$</c>.</param>
    public JsonataVariableExpression(string name)
    {
        Name = name;
    }
}


/// <summary>
/// An object construction: an ordered list of <c>"key": expr</c> members evaluated into a JSON
/// object — the credential body the VCALM template builds. Member order is preserved.
/// </summary>
public sealed class JsonataObjectExpression: JsonataExpression
{
    /// <summary>
    /// The members, in source order. Each pair is the member key and the expression producing its
    /// value.
    /// </summary>
    public IReadOnlyList<KeyValuePair<string, JsonataExpression>> Members { get; }


    /// <summary>
    /// Creates an object construction expression.
    /// </summary>
    /// <param name="members">The members, in source order.</param>
    public JsonataObjectExpression(IReadOnlyList<KeyValuePair<string, JsonataExpression>> members)
    {
        Members = members;
    }
}


/// <summary>
/// An array construction: an ordered list of element expressions evaluated into a JSON array.
/// </summary>
public sealed class JsonataArrayExpression: JsonataExpression
{
    /// <summary>
    /// The element expressions, in source order.
    /// </summary>
    public IReadOnlyList<JsonataExpression> Elements { get; }


    /// <summary>
    /// Creates an array construction expression.
    /// </summary>
    /// <param name="elements">The element expressions, in source order.</param>
    public JsonataArrayExpression(IReadOnlyList<JsonataExpression> elements)
    {
        Elements = elements;
    }
}


/// <summary>
/// A string concatenation: <c>left &amp; right</c>. Both operands are evaluated and rendered to their
/// string form, then joined. This is the only operator the minimal evaluator implements.
/// </summary>
public sealed class JsonataConcatExpression: JsonataExpression
{
    /// <summary>
    /// The left operand.
    /// </summary>
    public JsonataExpression Left { get; }

    /// <summary>
    /// The right operand.
    /// </summary>
    public JsonataExpression Right { get; }


    /// <summary>
    /// Creates a concatenation expression.
    /// </summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    public JsonataConcatExpression(JsonataExpression left, JsonataExpression right)
    {
        Left = left;
        Right = right;
    }
}
