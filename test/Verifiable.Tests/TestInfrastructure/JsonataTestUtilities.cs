using Lumoin.Veritas.Core.Injection;
using Lumoin.Veritas.Json;
using Lumoin.Veritas.Json.Stj;
using Microsoft.Extensions.Time.Testing;
using System.Text;
using System.Text.Json;
using Verifiable.Vcalm;
using VeritasJsonata = Lumoin.Veritas.Jsonata.Jsonata;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Wires the real <c>Lumoin.Veritas.Jsonata</c> engine onto the W3C VCALM 1.0 §3.6.1 credential-
/// template evaluation seam (<see cref="VcalmTemplateEvaluator"/>): the byte-in/byte-out
/// <c>Jsonata.Evaluate</c> overload takes the template and the composed variables as raw UTF-8 JSON
/// and returns the rendered credential body already serialized, so the seam's evaluator does no
/// value-model translation of its own — it copies the returned bytes into the caller's pooled
/// carrier.
/// </summary>
/// <remarks>
/// Variables reach a template two ways, matching the VCALM convention: as the JSONata <c>input</c>
/// document (so a bare path <c>name</c> navigates the variables object) and as caller bindings (so
/// <c>$name</c> resolves the same member) — the latter built here by parsing the composed variables
/// with <see cref="JsonDocument"/> (test infrastructure is free of the <c>System.Text.Json</c> ban
/// that applies inside <c>Verifiable.Vcalm</c>) and adapting each top-level member through
/// <see cref="StjJsonAdapter.From(JsonElement)"/>.
/// </remarks>
internal static class JsonataTestUtilities
{
    /// <summary>
    /// Creates the Veritas-backed template evaluator for the <c>jsonata</c> template type, to
    /// register through <see cref="VcalmTemplateEvaluatorRegistry.Register"/>.
    /// </summary>
    /// <param name="timeProvider">The clock the engine's date/time builtins read; the suite's canonical fixture.</param>
    /// <param name="randomness">The entropy source the engine's random/uuid builtins read; a deterministic test source.</param>
    /// <returns>The evaluator delegate.</returns>
    public static VcalmTemplateEvaluator CreateVeritasTemplateEvaluator(
        TimeProvider timeProvider, RandomnessDelegate randomness)
    {
        return (template, variablesJson, pool, cancellationToken) =>
        {
            using var enginePool = new Utf8StringPool();
            byte[] expression = Encoding.UTF8.GetBytes(template.Template);

            //The bindings' JsonNode values wrap JsonElements backed by this JsonDocument's buffer, so
            //the document must outlive the Evaluate call that reads them — it is disposed only after
            //the engine has finished, not inside the helper that builds the bindings.
            using JsonDocument? variablesDocument = OpenVariablesDocument(variablesJson);
            Dictionary<string, JsonNode> bindings = BuildBindings(variablesDocument);

            ReadOnlyMemory<byte> rendered = VeritasJsonata.Evaluate(
                expression, variablesJson, StjJsonAdapter.Parse, enginePool, bindings, timeProvider, randomness);

            return rendered.IsEmpty ? null : PooledMemory.FromBytes(rendered.Span, pool, BufferTags.Json);
        };
    }


    /// <summary>
    /// Creates a registry whose <c>jsonata</c> evaluator is the Veritas engine, with the seam's own
    /// <see cref="VcalmTemplateLimits"/> assigned explicitly (defaulting to a fresh instance, so a
    /// caller sees the assignment and can override it). The engine's OWN internal evaluation bounds
    /// (<c>Lumoin.Veritas.Jsonata.JsonataLimits</c>) are process-wide static fields with no per-call
    /// or per-instance configuration surface on the byte-typed <c>Evaluate</c> overload this seam
    /// calls — mutating them here would race every other test in the same process, so this sample
    /// leaves them at whatever the engine assembly ships, and a caller that needs to exercise them
    /// (as <see cref="Verifiable.Tests.Vcalm.VcalmVeritasTemplateEvaluatorTests.OversizedTemplateIsRefusedByTheExpressionBound"/>
    /// does) reads them rather than sets them.
    /// </summary>
    /// <param name="timeProvider">The clock the engine reads; defaults to the suite's canonical fixture.</param>
    /// <param name="randomness">The entropy source the engine reads; defaults to a deterministic test source.</param>
    /// <param name="limits">The seam's own size bounds; defaults to <see cref="VcalmTemplateLimits"/>'s defaults, assigned explicitly rather than left implicit.</param>
    /// <returns>The registry.</returns>
    public static VcalmTemplateEvaluatorRegistry CreateVeritasTemplateRegistry(
        TimeProvider? timeProvider = null, RandomnessDelegate? randomness = null, VcalmTemplateLimits? limits = null)
    {
        RandomnessDelegate effectiveRandomness = randomness ?? DeterministicRandomness;
        var registry = new VcalmTemplateEvaluatorRegistry
        {
            Limits = limits ?? new VcalmTemplateLimits()
        };
        registry.Register(
            VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            CreateVeritasTemplateEvaluator(
                timeProvider ?? new FakeTimeProvider(TestClock.CanonicalEpoch),
                effectiveRandomness));

        return registry;
    }


    /// <summary>
    /// Parses the composed variables bytes once, or returns <see langword="null"/> for an empty
    /// fragment; the caller keeps the document alive for as long as any <see cref="JsonNode"/> built
    /// from it is read.
    /// </summary>
    /// <param name="variablesJson">The composed variables document, as UTF-8 JSON.</param>
    /// <returns>The parsed document, or <see langword="null"/> for an empty fragment.</returns>
    private static JsonDocument? OpenVariablesDocument(ReadOnlyMemory<byte> variablesJson) =>
        variablesJson.IsEmpty ? null : JsonDocument.Parse(variablesJson);


    /// <summary>
    /// Builds the <c>$</c>-prefixed caller bindings for the top-level members of the composed
    /// variables object, so both <c>$name</c> and the bare input-document path resolve the same
    /// variable. A non-object (or absent) variables document yields no bindings — the input-document
    /// route still resolves bare paths against whatever <c>VeritasJsonata.Evaluate</c> parses from
    /// the raw bytes.
    /// </summary>
    /// <param name="variablesDocument">The parsed variables document, or <see langword="null"/>.</param>
    /// <returns>The <c>$</c>-prefixed bindings, empty when <paramref name="variablesDocument"/> is not an object.</returns>
    private static Dictionary<string, JsonNode> BuildBindings(JsonDocument? variablesDocument)
    {
        var bindings = new Dictionary<string, JsonNode>(StringComparer.Ordinal);
        if(variablesDocument is null || variablesDocument.RootElement.ValueKind != JsonValueKind.Object)
        {
            return bindings;
        }

        foreach(JsonProperty property in variablesDocument.RootElement.EnumerateObject())
        {
            bindings[property.Name] = StjJsonAdapter.From(property.Value);
        }

        return bindings;
    }


    /// <summary>
    /// A deterministic randomness source for tests: a fixed value per <see cref="RandomnessKind"/>,
    /// never the real entropy source — the suite never depends on which random value a template's
    /// <c>$random()</c> / <c>$uuid()</c> call produces.
    /// </summary>
    /// <param name="request">The engine's randomness request.</param>
    /// <returns>A fixed value matching the requested kind.</returns>
    public static RandomnessValue DeterministicRandomness(in RandomnessRequest request) => request.Kind switch
    {
        RandomnessKind.UniformDouble => new RandomnessValue(request.Kind, 0.5d, Guid.Empty, ReadOnlyMemory<byte>.Empty),
        RandomnessKind.Uuid => new RandomnessValue(
            request.Kind, 0d, Guid.Parse("00000000-0000-0000-0000-000000000001"), ReadOnlyMemory<byte>.Empty),
        _ => new RandomnessValue(request.Kind, 0d, Guid.Empty, new byte[request.ByteCount])
    };
}
