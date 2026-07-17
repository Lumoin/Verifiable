using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core.Did.Methods.WebPlus;

namespace Verifiable.Json;

/// <summary>
/// Parses a did:webplus <c>updateRules</c> expression into a <see cref="WebPlusUpdateRule"/> tree (did:webplus
/// Draft v0.4, Update Rules; WP-UR-1). <c>Verifiable.Core</c> is firewalled from a JSON serializer, so the JSON
/// parsing lives here while the rule model and its evaluation stay in <c>Verifiable.Core</c>.
/// </summary>
/// <remarks>
/// The conversion of the parsed JSON tree into the typed rule tree is iterative (an explicit
/// <see cref="Stack{T}"/> of build frames, no recursion — the same shape as the evaluation walk in
/// <see cref="WebPlusUpdateRuleEvaluation"/>), and the JSON parse bounds its depth, so an adversarially deep
/// <c>updateRules</c> cannot overflow the stack. A malformed expression is rejected by throwing.
/// </remarks>
public static class WebPlusUpdateRulesJson
{
    private static string UpdateRulesProperty { get; } = WellKnownWebPlusValues.UpdateRulesField;
    private static string KeyProperty { get; } = WellKnownWebPlusValues.UpdateRuleKey;
    private static string HashedKeyProperty { get; } = WellKnownWebPlusValues.UpdateRuleHashedKey;
    private static string AnyProperty { get; } = WellKnownWebPlusValues.UpdateRuleAny;
    private static string AllProperty { get; } = WellKnownWebPlusValues.UpdateRuleAll;
    private static string AtLeastProperty { get; } = WellKnownWebPlusValues.UpdateRuleAtLeast;
    private static string OfProperty { get; } = WellKnownWebPlusValues.UpdateRuleOf;
    private static string WeightProperty { get; } = WellKnownWebPlusValues.UpdateRuleWeight;

    //did:webplus update rules nest (any/all/atLeast), but an adversarial document could nest them deeply; bound
    //the JSON parse depth so a hostile updateRules cannot exhaust the parse, matching the bound used elsewhere
    //for untrusted JSON. Duplicate property names are rejected (AllowDuplicateProperties = false): a self-hashed,
    //self-certifying document MUST have one unambiguous byte form, and RFC 8785 Section 3.1 leaves JCS over
    //duplicate keys undefined, so a duplicated member is a malformed document rather than a last-wins silent pick.
    private static JsonDocumentOptions ParseOptions { get; } = new() { MaxDepth = 32, AllowDuplicateProperties = false };

    //A did:webplus 'atLeast' threshold and every explicit weight MUST be a positive integer: a non-positive
    //threshold is satisfied by zero proofs (a keyless takeover of a degenerate rule), and a non-positive weight
    //contributes nothing or subtracts from the satisfied weight — neither expresses a meaningful authorization.
    private const int MinimumThreshold = 1;
    private const int MinimumWeight = 1;

    //The rule-shape discriminators an update rule object may carry. A did:webplus update rule MUST be exactly one
    //of the defined forms (WP-UR-1), so an object naming more than one of these is ambiguous and rejected rather
    //than silently resolved by the parser's internal precedence.
    private static string[] RuleDiscriminators { get; } =
        [KeyProperty, HashedKeyProperty, AnyProperty, AllProperty, AtLeastProperty];


    /// <summary>
    /// The <see cref="WebPlusUpdateRuleParser"/> that reads a DID document's <c>updateRules</c> and parses it
    /// into a <see cref="WebPlusUpdateRule"/> tree.
    /// </summary>
    public static WebPlusUpdateRuleParser Parser { get; } = ParseFromDocument;


    private static WebPlusUpdateRule ParseFromDocument(ReadOnlySpan<byte> didDocumentJson)
    {
        JsonObject document = JsonNode.Parse(didDocumentJson, nodeOptions: null, ParseOptions) as JsonObject
            ?? throw new JsonException("A did:webplus DID document MUST be a JSON object.");

        if(!document.TryGetPropertyValue(UpdateRulesProperty, out JsonNode? updateRules) || updateRules is null)
        {
            throw new JsonException("A did:webplus DID document MUST have an 'updateRules' field.");
        }

        return ParseRule(updateRules);
    }


    //Iterative parse (explicit stack, no recursion): a leaf rule builds immediately; a composite (any/all/atLeast)
    //pushes a frame whose children are folded in as they finish, exactly mirroring WebPlusUpdateRuleEvaluation's
    //evaluation walk. Only the top-level rule may be the `{}` disallow form; a child MUST be a defined non-root
    //rule.
    private static WebPlusUpdateRule ParseRule(JsonNode root)
    {
        if(!IsComposite(root))
        {
            return BuildLeaf(root, allowDisallow: true);
        }

        var stack = new Stack<BuildFrame>();
        stack.Push(BuildFrame.For(root));

        WebPlusUpdateRule? finalResult = null;
        while(stack.Count > 0)
        {
            BuildFrame frame = stack.Peek();
            if(frame.Index < frame.ChildCount)
            {
                JsonNode child = frame.ChildAt(frame.Index);
                if(IsComposite(child))
                {
                    stack.Push(BuildFrame.For(child));
                }
                else
                {
                    frame.AddChild(BuildLeaf(child, allowDisallow: false));
                    frame.Index++;
                }
            }
            else
            {
                WebPlusUpdateRule built = frame.Build();
                stack.Pop();
                if(stack.Count > 0)
                {
                    BuildFrame parent = stack.Peek();
                    parent.AddChild(built);
                    parent.Index++;
                }
                else
                {
                    finalResult = built;
                }
            }
        }

        return finalResult!;
    }


    //A composite rule is a JSON object carrying an `any`, `all` or `atLeast` member; everything else is a leaf
    //(key/hashedKey/disallow).
    private static bool IsComposite(JsonNode node)
    {
        return node is JsonObject o && (o.ContainsKey(AnyProperty) || o.ContainsKey(AllProperty) || o.ContainsKey(AtLeastProperty));
    }


    //Builds a leaf rule: a `key` or `hashedKey` rule, or — only when allowed (the top-level form) — the `{}`
    //disallow rule. A non-root position requires a defined rule, so an object with no rule member there is
    //rejected rather than silently treated as disallow.
    private static WebPlusUpdateRule BuildLeaf(JsonNode node, bool allowDisallow)
    {
        if(node is not JsonObject o)
        {
            throw new JsonException("A did:webplus update rule MUST be a JSON object.");
        }

        RejectAmbiguousDiscriminators(o);

        if(o.ContainsKey(KeyProperty))
        {
            return new KeyUpdateRule(RequireString(o, KeyProperty));
        }

        if(o.ContainsKey(HashedKeyProperty))
        {
            return new HashedKeyUpdateRule(RequireString(o, HashedKeyProperty));
        }

        if(allowDisallow)
        {
            //`{}` disallows updates (the deactivation tombstone). A stray `weight` does not define a rule, so any
            //top-level object with no rule member is the disallow form.
            return new DisallowUpdateRule();
        }

        throw new JsonException("A did:webplus non-root update rule MUST be a 'key', 'hashedKey', 'any', 'all' or 'atLeast' rule.");
    }


    private static string RequireString(JsonObject o, string property)
    {
        if(o[property] is JsonValue value && value.GetValueKind() == JsonValueKind.String && value.TryGetValue(out string? text))
        {
            return text;
        }

        throw new JsonException($"A did:webplus update rule '{property}' MUST be a string.");
    }


    //Rejects a rule object that names more than one shape discriminator (key/hashedKey/any/all/atLeast). WP-UR-1
    //fixes a rule as exactly one of the defined forms; an object carrying several would otherwise be resolved by
    //the parser's internal precedence, so two conformant implementations could derive different authorization
    //policies from byte-identical content. Such an object is malformed and rejected rather than silently narrowed.
    private static void RejectAmbiguousDiscriminators(JsonObject rule)
    {
        int discriminatorCount = 0;
        for(int i = 0; i < RuleDiscriminators.Length; i++)
        {
            if(rule.ContainsKey(RuleDiscriminators[i]))
            {
                discriminatorCount++;
            }
        }

        if(discriminatorCount > 1)
        {
            throw new JsonException(
                "A did:webplus update rule MUST be exactly one of the defined forms ('key', 'hashedKey', 'any', 'all' or 'atLeast'); an object naming more than one is ambiguous.");
        }
    }


    /// <summary>
    /// A composite rule mid-construction: the composite kind, the JSON array of its children, a cursor, and the
    /// builders that accumulate the typed children. Held as a class frame on the explicit parse stack.
    /// </summary>
    private sealed class BuildFrame
    {
        /// <summary>The composite kind (any/all/atLeast) this frame builds.</summary>
        private CompositeKind Kind { get; }

        /// <summary>The JSON array of the composite's child rule nodes.</summary>
        private JsonArray Children { get; }

        /// <summary>The <c>atLeast</c> threshold (0 for an <c>any</c>/<c>all</c> frame, which does not use it).</summary>
        private int Threshold { get; }

        /// <summary>The accumulator of an <c>any</c>/<c>all</c> frame's built children (null for an <c>atLeast</c> frame).</summary>
        private ImmutableArray<WebPlusUpdateRule>.Builder? SimpleChildren { get; }

        /// <summary>The accumulator of an <c>atLeast</c> frame's built weighted children (null otherwise).</summary>
        private ImmutableArray<WeightedUpdateRule>.Builder? WeightedChildren { get; }

        private BuildFrame(CompositeKind kind, JsonArray children, int threshold)
        {
            Kind = kind;
            Children = children;
            Threshold = threshold;
            if(kind == CompositeKind.AtLeast)
            {
                WeightedChildren = ImmutableArray.CreateBuilder<WeightedUpdateRule>(children.Count);
            }
            else
            {
                SimpleChildren = ImmutableArray.CreateBuilder<WebPlusUpdateRule>(children.Count);
            }
        }

        /// <summary>The index of the next child to parse.</summary>
        public int Index { get; set; }

        /// <summary>The number of child rules.</summary>
        public int ChildCount => Children.Count;

        /// <summary>The child JSON node at <paramref name="index"/>.</summary>
        /// <param name="index">The child index.</param>
        /// <returns>The child node.</returns>
        public JsonNode ChildAt(int index)
        {
            return Children[index] ?? throw new JsonException("A did:webplus composite update rule MUST NOT contain a null sub-rule.");
        }

        /// <summary>Folds a built child rule into the accumulator (attaching its weight for an <c>atLeast</c>).</summary>
        /// <param name="rule">The built child rule at <see cref="Index"/>.</param>
        public void AddChild(WebPlusUpdateRule rule)
        {
            if(Kind == CompositeKind.AtLeast)
            {
                WeightedChildren!.Add(new WeightedUpdateRule(WeightAt(Index), rule));
            }
            else
            {
                SimpleChildren!.Add(rule);
            }
        }

        /// <summary>Constructs the composite rule once all children have been folded in.</summary>
        /// <returns>The built composite rule.</returns>
        public WebPlusUpdateRule Build()
        {
            return Kind switch
            {
                CompositeKind.Any => new AnyUpdateRule(SimpleChildren!.ToImmutable()),
                CompositeKind.All => new AllUpdateRule(SimpleChildren!.ToImmutable()),
                CompositeKind.AtLeast => new AtLeastUpdateRule(Threshold, WeightedChildren!.ToImmutable()),
                _ => throw new JsonException("Unknown did:webplus composite update rule.")
            };
        }

        //The weight of the `of` element at index: its `weight` member, or 1 when absent (did:webplus Update
        //Rules — a WeightedUpdateRules without a `weight` has weight 1).
        private int WeightAt(int index)
        {
            if(Children[index] is JsonObject o && o.TryGetPropertyValue(WeightProperty, out JsonNode? weightNode) && weightNode is not null)
            {
                if(weightNode is JsonValue value && value.GetValueKind() == JsonValueKind.Number && value.TryGetValue(out int weight))
                {
                    if(weight < MinimumWeight)
                    {
                        throw new JsonException($"A did:webplus update rule 'weight' MUST be at least {MinimumWeight}.");
                    }

                    return weight;
                }

                throw new JsonException("A did:webplus update rule 'weight' MUST be an integer.");
            }

            return 1;
        }

        /// <summary>Creates a frame for a composite rule object, reading the threshold for an <c>atLeast</c>.</summary>
        /// <param name="node">The composite rule node.</param>
        /// <returns>The new build frame.</returns>
        public static BuildFrame For(JsonNode node)
        {
            var o = (JsonObject)node;

            RejectAmbiguousDiscriminators(o);

            if(o.ContainsKey(AnyProperty))
            {
                return new BuildFrame(CompositeKind.Any, RequireArray(o, AnyProperty), threshold: 0);
            }

            if(o.ContainsKey(AllProperty))
            {
                return new BuildFrame(CompositeKind.All, RequireArray(o, AllProperty), threshold: 0);
            }

            return new BuildFrame(CompositeKind.AtLeast, RequireArray(o, OfProperty), RequireThreshold(o));
        }

        private static JsonArray RequireArray(JsonObject o, string property)
        {
            JsonArray array = o[property] as JsonArray
                ?? throw new JsonException($"A did:webplus update rule '{property}' MUST be an array.");

            if(array.Count == 0)
            {
                throw new JsonException(
                    $"A did:webplus update rule '{property}' MUST be a non-empty array; an empty '{property}' has no meaningful authorization semantics (an empty 'all' would otherwise be satisfied by no proofs).");
            }

            return array;
        }

        private static int RequireThreshold(JsonObject o)
        {
            if(o[AtLeastProperty] is JsonValue value && value.GetValueKind() == JsonValueKind.Number && value.TryGetValue(out int threshold))
            {
                if(threshold < MinimumThreshold)
                {
                    throw new JsonException(
                        $"A did:webplus 'atLeast' update rule threshold MUST be at least {MinimumThreshold}; a non-positive threshold is satisfied with no proofs.");
                }

                return threshold;
            }

            throw new JsonException("A did:webplus 'atLeast' update rule threshold MUST be an integer.");
        }
    }


    /// <summary>The composite did:webplus update-rule kinds.</summary>
    private enum CompositeKind
    {
        /// <summary>An <c>any</c> rule.</summary>
        Any,

        /// <summary>An <c>all</c> rule.</summary>
        All,

        /// <summary>An <c>atLeast</c> rule.</summary>
        AtLeast
    }
}