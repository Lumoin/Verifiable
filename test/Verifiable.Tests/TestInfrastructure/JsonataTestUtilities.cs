using Lumoin.Base;
using Lumoin.Veritas.Core;
using Lumoin.Veritas.Jsonata;
using Lumoin.Veritas.Jsonata.Execution;
using System.Text;
using Verifiable.Vcalm;
using NeutralKind = Verifiable.JsonPointer.Jsonata.JsonataValueKind;
using NeutralValue = Verifiable.JsonPointer.Jsonata.JsonataValue;
using VeritasKind = Lumoin.Veritas.Jsonata.Values.JsonataValueKind;
using VeritasValue = Lumoin.Veritas.Jsonata.Values.JsonataValue;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// JSONata wiring for tests: the Lumoin.Veritas engine adapted onto the VCALM 1.0 §3.6.1
/// credential-template seam (<see cref="VcalmTemplateEvaluator"/>) through the engine's AST route —
/// parse once, evaluate with the exchange variables as both the input document and the caller
/// bindings — plus the value-model adapter between the neutral template value and the engine's.
/// </summary>
/// <remarks>
/// <para>
/// Variables reach a template two ways, matching the VCALM convention: as the input document
/// (so a bare path <c>name</c> navigates the variables object) and as caller bindings (so
/// <c>$name</c> resolves the same member). The bindings ride the engine's
/// <c>IReadOnlyDictionary&lt;Utf8String, JsonataValue&gt;</c> parameter with bare member names as keys.
/// </para>
/// <para>
/// Value semantics follow the JSONata reference: JSON <c>null</c> is a value and survives into a
/// constructed object, whereas an undefined result is absence and its member is omitted. The
/// neutral model has no undefined, so an undefined evaluation result adapts to
/// <see cref="NeutralValue.Null"/> at the top level and to an omitted member inside an object.
/// Numbers are one JSONata type; a whole-valued result within the safe-integer range adapts back
/// to the neutral integer kind, everything else to the neutral number kind.
/// </para>
/// </remarks>
internal static class JsonataTestUtilities
{
    /// <summary>The largest whole number a double carries exactly, 2^53.</summary>
    private const double MaxSafeInteger = 9007199254740992d;


    /// <summary>
    /// Creates the Veritas-backed template evaluator for the <c>jsonata</c> template type, to
    /// register through <see cref="VcalmTemplateEvaluatorRegistry.Register"/>.
    /// </summary>
    /// <returns>The evaluator delegate.</returns>
    public static VcalmTemplateEvaluator CreateVeritasTemplateEvaluator()
    {
        return (template, variables) =>
        {
            using var pool = new Utf8StringPool();
            byte[] source = Encoding.UTF8.GetBytes(template.Template);
            var parsed = Jsonata.Parse(source, pool);
            if(parsed.HasErrors)
            {
                throw new InvalidOperationException(
                    $"The JSONata template failed to parse: {string.Join("; ", parsed.Diagnostics.Select(d => d.Message.ToString()))}");
            }

            VeritasValue input = ToVeritas(variables);
            Dictionary<Utf8String, VeritasValue>? bindings = null;
            if(variables.Kind == NeutralKind.Object)
            {
                bindings = new Dictionary<Utf8String, VeritasValue>();
                foreach((string name, NeutralValue value) in variables.AsObject())
                {
                    bindings[Utf8StringInterner.Shared.Intern(name)] = ToVeritas(value);
                }
            }

            VeritasValue result = JsonataEvaluator.Evaluate(parsed.Tree, input, pool, bindings);

            return ToNeutral(result);
        };
    }


    /// <summary>
    /// Creates a registry whose <c>jsonata</c> evaluator is the Veritas engine.
    /// </summary>
    /// <returns>The registry.</returns>
    public static VcalmTemplateEvaluatorRegistry CreateVeritasTemplateRegistry()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();
        registry.Register(VcalmTemplateEvaluatorRegistry.JsonataTemplateType, CreateVeritasTemplateEvaluator());

        return registry;
    }


    /// <summary>
    /// Adapts a neutral template value to the engine's value model.
    /// </summary>
    /// <param name="value">The neutral value.</param>
    /// <returns>The engine value.</returns>
    public static VeritasValue ToVeritas(NeutralValue value)
    {
        return value.Kind switch
        {
            NeutralKind.Null => VeritasValue.Null,
            NeutralKind.Boolean => VeritasValue.Boolean(value.AsBoolean()),
            NeutralKind.Integer => VeritasValue.Number(value.AsInteger()),
            NeutralKind.Number => VeritasValue.Number(value.AsNumber()),
            NeutralKind.String => VeritasValue.String(value.AsString()),
            NeutralKind.Array => VeritasValue.Array([.. value.AsArray().Select(ToVeritas)]),
            NeutralKind.Object => VeritasValue.Object(
                [.. value.AsObject().Select(member => new KeyValuePair<string, VeritasValue>(member.Key, ToVeritas(member.Value)))]),
            _ => throw new ArgumentOutOfRangeException(nameof(value), value.Kind, "Unknown neutral value kind.")
        };
    }


    /// <summary>
    /// Adapts an engine value to the neutral template value model.
    /// </summary>
    /// <param name="value">The engine value.</param>
    /// <returns>The neutral value.</returns>
    /// <exception cref="InvalidOperationException">The value is a function or a tuple stream, which JSON cannot carry.</exception>
    public static NeutralValue ToNeutral(VeritasValue value)
    {
        return value.Kind switch
        {
            VeritasKind.Undefined => NeutralValue.Null,
            VeritasKind.Null => NeutralValue.Null,
            VeritasKind.Boolean => NeutralValue.FromBoolean(value.AsBoolean),
            VeritasKind.Number => ToNeutralNumber(value.AsNumber),
            VeritasKind.String => NeutralValue.FromString(value.AsString),
            VeritasKind.Array => NeutralValue.FromArray([.. value.AsArray.Where(item => !item.IsUndefined).Select(ToNeutral)]),
            VeritasKind.Object => ToNeutralObject(value),
            _ => throw new InvalidOperationException($"A JSONata {value.Kind} value has no JSON representation.")
        };
    }


    //A whole-valued number within the safe-integer range becomes the neutral integer kind; a
    //fractional or out-of-range one stays a number.
    private static NeutralValue ToNeutralNumber(double number)
    {
        return Math.Abs(number) < MaxSafeInteger && Math.Floor(number) == number
            ? NeutralValue.FromInteger((long)number)
            : NeutralValue.FromNumber(number);
    }


    //Explicit null members survive; undefined-valued members are absence and are omitted, per
    //the JSONata object-construction semantics.
    private static NeutralValue ToNeutralObject(VeritasValue value)
    {
        var members = new Dictionary<string, NeutralValue>(StringComparer.Ordinal);
        foreach((string key, VeritasValue member) in value.AsObject)
        {
            if(!member.IsUndefined)
            {
                members[key] = ToNeutral(member);
            }
        }

        return NeutralValue.FromObject(members);
    }
}
