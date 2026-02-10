using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.JsonPointer;
using Rfc6901JsonPointer = Verifiable.JsonPointer.JsonPointer;

namespace Verifiable.Json;

/// <summary>
/// Provides JSON-LD fragment selection for selective disclosure proofs using System.Text.Json.
/// </summary>
/// <remarks>
/// <para>
/// This class implements the fragment selection needed for ecdsa-sd-2023 and similar
/// selective disclosure cryptosuites. It operates on compact JSON-LD documents using
/// pure JSON operations, then relies on an external canonicalizer (like dotNetRDF)
/// to convert fragments to N-Quads.
/// </para>
/// <para>
/// The approach mirrors Digital Bazaar's <c>di-sd-primitives</c>: JSON manipulation
/// is done independently, and the RDF library is used as a black box for canonicalization.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#selectjsonld">
/// VC Data Integrity ECDSA: selectJsonLd algorithm</see>.
/// </para>
/// </remarks>
public static class JsonLdSelection
{
    /// <summary>
    /// Selects a fragment from a JSON-LD document using a JSON Pointer.
    /// </summary>
    /// <param name="document">The compact JSON-LD document.</param>
    /// <param name="pointer">The JSON Pointer identifying the fragment.</param>
    /// <returns>
    /// A valid JSON-LD document containing only the selected fragment,
    /// wrapped with the original context and necessary path structure.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the pointer does not resolve to a value in the document.
    /// </exception>
    /// <remarks>
    /// <para>
    /// The returned document is a valid JSON-LD that can be canonicalized.
    /// It includes:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The <c>@context</c> from the original document.</description></item>
    /// <item><description>Any <c>id</c> and <c>type</c> values along the path.</description></item>
    /// <item><description>The selected value at its original path location.</description></item>
    /// </list>
    /// </remarks>
    public static string SelectFragment(string document, Rfc6901JsonPointer pointer)
    {
        ArgumentException.ThrowIfNullOrEmpty(document);

        using JsonDocument doc = JsonDocument.Parse(document);
        JsonElement root = doc.RootElement;

        //Build a selection document with context.
        var selection = new JsonObject();

        //Copy @context from root.
        if(root.TryGetProperty("@context", out JsonElement context))
        {
            selection["@context"] = JsonNode.Parse(context.GetRawText());
        }

        //Copy root id if present (non-blank node).
        if(root.TryGetProperty("id", out JsonElement rootId))
        {
            string? idValue = rootId.GetString();
            if(idValue is not null && !idValue.StartsWith("_:", StringComparison.Ordinal))
            {
                selection["id"] = idValue;
            }
        }

        //Copy root type if present.
        if(root.TryGetProperty("type", out JsonElement rootType))
        {
            selection["type"] = JsonNode.Parse(rootType.GetRawText());
        }

        //If pointer is root, we're done.
        if(pointer.IsRoot)
        {
            return selection.ToJsonString();
        }

        //Navigate and build path.
        BuildSelectionPath(root, pointer, selection);

        return selection.ToJsonString();
    }


    /// <summary>
    /// Selects fragments for multiple pointers and merges them.
    /// </summary>
    /// <param name="document">The compact JSON-LD document.</param>
    /// <param name="pointers">The JSON Pointers identifying fragments.</param>
    /// <returns>
    /// A valid JSON-LD document containing all selected fragments merged together.
    /// </returns>
    public static string SelectFragments(string document, IEnumerable<Rfc6901JsonPointer> pointers)
    {
        ArgumentException.ThrowIfNullOrEmpty(document);
        ArgumentNullException.ThrowIfNull(pointers);

        using JsonDocument doc = JsonDocument.Parse(document);
        JsonElement root = doc.RootElement;

        //Build a selection document with context.
        var selection = new JsonObject();

        //Copy @context from root.
        if(root.TryGetProperty("@context", out JsonElement context))
        {
            selection["@context"] = JsonNode.Parse(context.GetRawText());
        }

        //Copy root id if present (non-blank node).
        if(root.TryGetProperty("id", out JsonElement rootId))
        {
            string? idValue = rootId.GetString();
            if(idValue is not null && !idValue.StartsWith("_:", StringComparison.Ordinal))
            {
                selection["id"] = idValue;
            }
        }

        //Copy root type if present.
        if(root.TryGetProperty("type", out JsonElement rootType))
        {
            selection["type"] = JsonNode.Parse(rootType.GetRawText());
        }

        //Build paths for each pointer.
        foreach(Rfc6901JsonPointer pointer in pointers)
        {
            if(!pointer.IsRoot)
            {
                BuildSelectionPath(root, pointer, selection);
            }
        }

        return selection.ToJsonString();
    }


    /// <summary>
    /// Evaluates a JSON Pointer against a document.
    /// </summary>
    /// <param name="root">The root JSON element.</param>
    /// <param name="pointer">The pointer to evaluate.</param>
    /// <param name="result">The element at the pointer location if found.</param>
    /// <returns><see langword="true"/> if the pointer resolved; otherwise <see langword="false"/>.</returns>
    public static bool TryEvaluate(JsonElement root, Rfc6901JsonPointer pointer, out JsonElement result)
    {
        result = root;

        if(pointer.IsRoot)
        {
            return true;
        }

        foreach(JsonPointerSegment segment in pointer.Segments)
        {
            if(result.ValueKind == JsonValueKind.Object)
            {
                if(!result.TryGetProperty(segment.Value, out result))
                {
                    result = default;
                    return false;
                }
            }
            else if(result.ValueKind == JsonValueKind.Array)
            {
                if(!segment.TryGetArrayIndex(out int index))
                {
                    result = default;
                    return false;
                }

                int length = result.GetArrayLength();
                if(index >= length)
                {
                    result = default;
                    return false;
                }

                result = result[index];
            }
            else
            {
                //Scalar node cannot be navigated further.
                result = default;
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Partitions N-Quad statements into mandatory and non-mandatory sets based on JSON Pointers.
    /// </summary>
    /// <param name="document">The compact JSON-LD document.</param>
    /// <param name="mandatoryPointers">JSON Pointers identifying mandatory claims.</param>
    /// <param name="canonicalize">The canonicalization delegate (JSON-LD → N-Quads).</param>
    /// <param name="contextResolver">
    /// Optional delegate for resolving JSON-LD contexts during canonicalization.
    /// Required for RDFC canonicalization, ignored by JCS canonicalization.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A task that resolves to the partition result containing statements and their indexes.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method implements the statement partitioning needed for ecdsa-sd-2023:
    /// </para>
    /// <list type="number">
    /// <item><description>Canonicalize the full document to get all N-Quads.</description></item>
    /// <item><description>Select mandatory fragments using JSON Pointers.</description></item>
    /// <item><description>Canonicalize the mandatory selection.</description></item>
    /// <item><description>Match to determine which full N-Quads are mandatory.</description></item>
    /// </list>
    /// <para>
    /// The returned indexes can be applied to HMAC-relabeled statements since the
    /// relabeling preserves statement order.
    /// </para>
    /// </remarks>
    public static async ValueTask<StatementPartitionResult> PartitionStatements(
        string document,
        IReadOnlyList<Rfc6901JsonPointer> mandatoryPointers,
        CanonicalizationDelegate canonicalize,
        ContextResolverDelegate? contextResolver,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(document);
        ArgumentNullException.ThrowIfNull(mandatoryPointers);
        ArgumentNullException.ThrowIfNull(canonicalize);

        //Canonicalize the full document.
        string fullNQuads = await canonicalize(document, contextResolver, cancellationToken).ConfigureAwait(false);
        string[] rawStatements = fullNQuads.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        //Each N-Quad statement must end with newline per W3C spec for correct hashing.
        string[] allStatements = [.. rawStatements.Select(s => s + "\n")];

        if(mandatoryPointers.Count == 0)
        {
            //No mandatory pointers — all statements are non-mandatory.
            var allNonMandatoryIndexes = new List<int>(allStatements.Length);
            for(int i = 0; i < allStatements.Length; i++)
            {
                allNonMandatoryIndexes.Add(i);
            }

            return new StatementPartitionResult(
                allStatements,
                MandatoryIndexes: [],
                NonMandatoryIndexes: allNonMandatoryIndexes);
        }

        //Select and canonicalize the mandatory fragments.
        string mandatorySelection = SelectFragments(document, mandatoryPointers);
        string mandatoryNQuads = await canonicalize(mandatorySelection, contextResolver, cancellationToken).ConfigureAwait(false);
        string[] rawMandatoryStatements = mandatoryNQuads.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string[] mandatoryStatements = [.. rawMandatoryStatements.Select(s => s + "\n")];

        //Build a set of mandatory statements for O(1) lookup.
        var mandatorySet = new HashSet<string>(mandatoryStatements, StringComparer.Ordinal);

        //Partition by matching.
        var mandatoryIndexes = new List<int>();
        var nonMandatoryIndexes = new List<int>();

        for(int i = 0; i < allStatements.Length; i++)
        {
            if(mandatorySet.Contains(allStatements[i]))
            {
                mandatoryIndexes.Add(i);
            }
            else
            {
                nonMandatoryIndexes.Add(i);
            }
        }

        return new StatementPartitionResult(
            allStatements,
            mandatoryIndexes,
            nonMandatoryIndexes);
    }


    private static void BuildSelectionPath(
        JsonElement source,
        Rfc6901JsonPointer pointer,
        JsonObject selection)
    {
        JsonElement current = source;
        JsonObject currentSelection = selection;

        ReadOnlySpan<JsonPointerSegment> segments = pointer.Segments;

        for(int i = 0; i < segments.Length; i++)
        {
            JsonPointerSegment segment = segments[i];
            bool isLast = i == segments.Length - 1;

            if(current.ValueKind == JsonValueKind.Object)
            {
                string token = segment.Value;

                if(!current.TryGetProperty(token, out JsonElement child))
                {
                    throw new ArgumentException(
                        $"JSON Pointer '{pointer}' does not resolve: property '{token}' not found.",
                        nameof(pointer));
                }

                if(isLast)
                {
                    //Add the final value.
                    currentSelection[token] = JsonNode.Parse(child.GetRawText());
                }
                else
                {
                    //Create intermediate object if needed.
                    if(!currentSelection.ContainsKey(token))
                    {
                        var intermediate = new JsonObject();

                        //Copy id and type from the child if present.
                        if(child.ValueKind == JsonValueKind.Object)
                        {
                            if(child.TryGetProperty("id", out JsonElement childId))
                            {
                                string? idValue = childId.GetString();
                                if(idValue is not null && !idValue.StartsWith("_:", StringComparison.Ordinal))
                                {
                                    intermediate["id"] = idValue;
                                }
                            }

                            if(child.TryGetProperty("type", out JsonElement childType))
                            {
                                intermediate["type"] = JsonNode.Parse(childType.GetRawText());
                            }
                        }

                        currentSelection[token] = intermediate;
                    }

                    currentSelection = currentSelection[token]!.AsObject();
                }

                current = child;
            }
            else if(current.ValueKind == JsonValueKind.Array)
            {
                if(!segment.TryGetArrayIndex(out int index))
                {
                    throw new ArgumentException(
                        $"JSON Pointer '{pointer}' does not resolve: token '{segment.Value}' is not a valid array index.",
                        nameof(pointer));
                }

                int length = current.GetArrayLength();
                if(index >= length)
                {
                    throw new ArgumentException(
                        $"JSON Pointer '{pointer}' does not resolve: array index {index} out of bounds (length {length}).",
                        nameof(pointer));
                }

                //For arrays, we need to handle this differently.
                //The spec says we need to preserve the array structure.
                //This is a simplified implementation — full spec compliance would need more work.
                throw new NotImplementedException(
                    "Array index selection in JSON Pointers is not yet fully implemented. " +
                    "Use property paths for now.");
            }
            else
            {
                throw new ArgumentException(
                    $"JSON Pointer '{pointer}' does not resolve: cannot navigate into scalar value.",
                    nameof(pointer));
            }
        }
    }
}