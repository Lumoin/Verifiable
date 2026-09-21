using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Json.Converters;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// <see cref="PropertySuppressingResolver"/> suppresses exactly the configured property from a target
/// type's serialization contract by transforming its configured CLR name through the active
/// <see cref="JsonSerializerOptions.PropertyNamingPolicy"/> and matching that transformed name against
/// each property's resolved <see cref="JsonPropertyInfo.Name"/>; it never inspects the underlying CLR
/// member through reflection.
/// </summary>
[TestClass]
internal sealed class PropertySuppressingResolverTests
{
    /// <summary>
    /// A minimal two-property type used to prove which property a configured suppression removes and
    /// which property it leaves serialized.
    /// </summary>
    private sealed class SamplePayload
    {
        public string Kept { get; set; } = string.Empty;

        public string Suppressed { get; set; } = string.Empty;
    }


    /// <summary>
    /// Suppresses <see cref="SamplePayload.Suppressed"/> from <see cref="SamplePayload"/> under the
    /// default (no) naming policy.
    /// </summary>
    private static JsonSerializerOptions DefaultPolicyOptions { get; } = new()
    {
        TypeInfoResolver = new PropertySuppressingResolver(
            new DefaultJsonTypeInfoResolver(), typeof(SamplePayload), nameof(SamplePayload.Suppressed))
    };

    /// <summary>
    /// Suppresses <see cref="SamplePayload.Suppressed"/> from <see cref="SamplePayload"/> under
    /// camelCase naming.
    /// </summary>
    private static JsonSerializerOptions CamelCasePolicyOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        TypeInfoResolver = new PropertySuppressingResolver(
            new DefaultJsonTypeInfoResolver(), typeof(SamplePayload), nameof(SamplePayload.Suppressed))
    };

    /// <summary>
    /// Configures suppression against <see cref="string"/>, a type <see cref="SamplePayload"/> is never
    /// assignable to, so the resolver must leave <see cref="SamplePayload"/>'s contract untouched.
    /// </summary>
    private static JsonSerializerOptions UnrelatedTargetOptions { get; } = new()
    {
        TypeInfoResolver = new PropertySuppressingResolver(
            new DefaultJsonTypeInfoResolver(), typeof(string), nameof(SamplePayload.Suppressed))
    };


    /// <summary>
    /// Under the default (no) naming policy, the resolved <see cref="JsonPropertyInfo.Name"/> equals the
    /// CLR property name, so the resolver suppresses the configured property and serializes every other
    /// declared property unchanged.
    /// </summary>
    [TestMethod]
    public void SuppressesConfiguredPropertyUnderDefaultNamingPolicy()
    {
        string json = JsonSerializer.Serialize(new SamplePayload { Kept = "a", Suppressed = "b" }, DefaultPolicyOptions);

        Assert.Contains("\"Kept\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Suppressed\"", json, StringComparison.Ordinal);
    }

    /// <summary>
    /// Under camelCase naming, the resolver transforms the configured CLR name through the same policy
    /// STJ applied to the property's resolved name before comparing, so the match still finds and
    /// suppresses the property under its transformed, camelCase name.
    /// </summary>
    [TestMethod]
    public void SuppressesConfiguredPropertyUnderCamelCaseNamingPolicy()
    {
        string json = JsonSerializer.Serialize(new SamplePayload { Kept = "a", Suppressed = "b" }, CamelCasePolicyOptions);

        Assert.Contains("\"kept\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"suppressed\"", json, StringComparison.Ordinal);
    }

    /// <summary>
    /// A type that is not assignable to the configured target type is returned exactly as the inner
    /// resolver produced it: the resolver never suppresses a property outside its configured target.
    /// </summary>
    [TestMethod]
    public void LeavesPropertiesOfAnUnrelatedTypeUntouched()
    {
        string json = JsonSerializer.Serialize(new SamplePayload { Kept = "a", Suppressed = "b" }, UnrelatedTargetOptions);

        Assert.Contains("\"Suppressed\"", json, StringComparison.Ordinal);
    }
}
