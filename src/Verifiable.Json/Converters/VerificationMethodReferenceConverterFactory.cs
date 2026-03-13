using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// A factory that creates converters for <see cref="VerificationMethodReference"/> subclasses.
/// </summary>
/// <remarks>
/// <para>
/// This factory creates type-specific converters for each verification relationship type
/// (<see cref="AuthenticationMethod"/>, <see cref="AssertionMethod"/>, etc.). The factory
/// pattern is required because System.Text.Json needs to instantiate the correct generic
/// converter for each concrete type.
/// </para>
/// <para>
/// A <see cref="VerificationMethodConverter"/> must be provided at construction and is
/// forwarded to each created converter. This avoids any runtime converter lookup
/// (which is <c>[RequiresUnreferencedCode, RequiresDynamicCode]</c>) and keeps
/// embedded <see cref="VerificationMethod"/> read/write fully AOT-safe.
/// </para>
/// <para>
/// <strong>Important:</strong> This factory only handles concrete subclasses, not the abstract
/// <see cref="VerificationMethodReference"/> base class directly. When deserializing properties
/// typed as the abstract base (such as in proof structures), the containing type's converter
/// must handle instantiation based on contextual information like <c>proofPurpose</c>.
/// </para>
/// </remarks>
public class VerificationMethodReferenceConverterFactory: JsonConverterFactory
{
    private readonly VerificationMethodConverter _vmConverter;

    /// <summary>
    /// Initializes the factory with the default <see cref="VerificationMethodConverter"/>.
    /// </summary>
    public VerificationMethodReferenceConverterFactory()
        : this(new VerificationMethodConverter()) { }

    /// <summary>
    /// Initializes the factory with a specific <see cref="VerificationMethodConverter"/>.
    /// </summary>
    /// <param name="vmConverter">
    /// The converter used to read and write embedded <see cref="VerificationMethod"/> objects.
    /// Must match the instance registered in <c>JsonSerializerOptions.Converters</c>.
    /// </param>
    public VerificationMethodReferenceConverterFactory(VerificationMethodConverter vmConverter)
    {
        ArgumentNullException.ThrowIfNull(vmConverter);
        _vmConverter = vmConverter;
    }


    /// <inheritdoc/>
    public override bool CanConvert(Type typeToConvert) => typeToConvert switch
    {
        var t when t == typeof(AuthenticationMethod) => true,
        var t when t == typeof(AssertionMethod) => true,
        var t when t == typeof(KeyAgreementMethod) => true,
        var t when t == typeof(CapabilityInvocationMethod) => true,
        var t when t == typeof(CapabilityDelegationMethod) => true,
        _ => false
    };


    /// <inheritdoc/>
    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) => typeToConvert switch
    {
        var t when t == typeof(AuthenticationMethod) =>
            new VerificationMethodReferenceConverter<AuthenticationMethod>(_vmConverter),
        var t when t == typeof(AssertionMethod) =>
            new VerificationMethodReferenceConverter<AssertionMethod>(_vmConverter),
        var t when t == typeof(KeyAgreementMethod) =>
            new VerificationMethodReferenceConverter<KeyAgreementMethod>(_vmConverter),
        var t when t == typeof(CapabilityInvocationMethod) =>
            new VerificationMethodReferenceConverter<CapabilityInvocationMethod>(_vmConverter),
        var t when t == typeof(CapabilityDelegationMethod) =>
            new VerificationMethodReferenceConverter<CapabilityDelegationMethod>(_vmConverter),
        _ => throw new JsonException($"No converter for verification method reference type '{typeToConvert}'.")
    };
}


/// <summary>
/// Converts <see cref="VerificationMethodReference"/> subclasses to and from JSON.
/// </summary>
/// <typeparam name="T">The specific verification relationship type.</typeparam>
/// <remarks>
/// <para>
/// Verification method references can be serialized in two forms:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>String:</strong> A DID URL reference like <c>"#key-1"</c> or
/// <c>"did:example:123#key-1"</c>.
/// </description></item>
/// <item><description>
/// <strong>Object:</strong> An embedded <see cref="VerificationMethod"/> with full key details.
/// The injected <see cref="VerificationMethodConverter"/> is invoked directly — no runtime
/// converter lookup, no source-gen <c>JsonTypeInfo</c> bypass, fully AOT-safe.
/// </description></item>
/// </list>
/// <para>
/// This converter is used for DID document verification relationships where the
/// property name determines the purpose (e.g., <c>authentication</c>, <c>assertionMethod</c>).
/// </para>
/// </remarks>
public class VerificationMethodReferenceConverter<T>: JsonConverter<T> where T : VerificationMethodReference
{
    private readonly VerificationMethodConverter _vmConverter;

    /// <summary>
    /// Initializes the converter with the <see cref="VerificationMethodConverter"/> to delegate to.
    /// </summary>
    public VerificationMethodReferenceConverter(VerificationMethodConverter vmConverter)
    {
        ArgumentNullException.ThrowIfNull(vmConverter);
        _vmConverter = vmConverter;
    }


    /// <inheritdoc/>
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.String && reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected string or object for verification method reference, but got {reader.TokenType}.");
        }

        if(reader.TokenType == JsonTokenType.String)
        {
            return CreateFromReferenceId(reader.GetString() ?? string.Empty);
        }

        var embedded = _vmConverter.Read(ref reader, typeof(VerificationMethod), options)!;
        return CreateFromEmbedded(embedded);
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        if(value.IsEmbeddedVerification)
        {
            _vmConverter.Write(writer, value.EmbeddedVerification!, options);
        }
        else
        {
            writer.WriteStringValue(value.VerificationReferenceId);
        }
    }


    /// <summary>
    /// Creates the appropriate <typeparamref name="T"/> from a DID URL reference string.
    /// </summary>
    private static T CreateFromReferenceId(string referenceId) =>
        (T)(VerificationMethodReference)(typeof(T) switch
        {
            var t when t == typeof(AuthenticationMethod) => new AuthenticationMethod(referenceId),
            var t when t == typeof(AssertionMethod) => new AssertionMethod(referenceId),
            var t when t == typeof(KeyAgreementMethod) => new KeyAgreementMethod(referenceId),
            var t when t == typeof(CapabilityInvocationMethod) => new CapabilityInvocationMethod(referenceId),
            var t when t == typeof(CapabilityDelegationMethod) => new CapabilityDelegationMethod(referenceId),
            _ => throw new JsonException($"No reference ID constructor mapping for type '{typeof(T)}'.")
        });


    /// <summary>
    /// Creates the appropriate <typeparamref name="T"/> from an embedded <see cref="VerificationMethod"/>.
    /// </summary>
    private static T CreateFromEmbedded(VerificationMethod embedded) =>
        (T)(VerificationMethodReference)(typeof(T) switch
        {
            var t when t == typeof(AuthenticationMethod) => new AuthenticationMethod(embedded),
            var t when t == typeof(AssertionMethod) => new AssertionMethod(embedded),
            var t when t == typeof(KeyAgreementMethod) => new KeyAgreementMethod(embedded),
            var t when t == typeof(CapabilityInvocationMethod) => new CapabilityInvocationMethod(embedded),
            var t when t == typeof(CapabilityDelegationMethod) => new CapabilityDelegationMethod(embedded),
            _ => throw new JsonException($"No embedded constructor mapping for type '{typeof(T)}'.")
        });
}