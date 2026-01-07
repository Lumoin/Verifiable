using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Describes how the bytes in <see cref="SensitiveMemory"/> should be interpreted
/// by bound cryptographic functions.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The Context Problem: Making Opaque Bytes Meaningful</strong>
/// </para>
/// <para>
/// Cryptographic material is fundamentally just bytes. Without metadata, these bytes are opaque:
/// Is this P-256 or Ed25519? Public or private key? Raw bytes or DER-encoded? Should it be
/// processed by software or delegated to a TPM? The bytes alone cannot answer these questions.
/// </para>
/// <para>
/// Existing systems solve this with format-specific identifiers:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>OIDs</strong> (e.g., 1.2.840.10045.3.1.7 for P-256) - verbose, require parsing,
/// not human-readable, tied to ASN.1/X.509 infrastructure.
/// </description></item>
/// <item><description>
/// <strong>JWT/JWA values</strong> (e.g., "ES256") - string comparison overhead, occasional
/// ambiguity, limited to JOSE ecosystem.
/// </description></item>
/// <item><description>
/// <strong>Class hierarchies</strong> (e.g., <c>P256PrivateKey</c>, <c>Ed25519PublicKey</c>) -
/// type explosion, cannot add algorithms without new classes, complicates generic code.
/// </description></item>
/// </list>
/// <para>
/// This library takes a different approach: bytes remain opaque, but are paired with a
/// <see cref="Tag"/> containing normalized context types (<see cref="CryptoAlgorithm"/>,
/// <see cref="Purpose"/>, <see cref="EncodingScheme"/>, <see cref="MaterialSemantics"/>).
/// This provides:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Format independence</strong> - same context system works across JOSE, COSE, DID,
/// X.509, and custom formats.
/// </description></item>
/// <item><description>
/// <strong>Fast routing</strong> - integer comparison, no string parsing or OID decoding.
/// </description></item>
/// <item><description>
/// <strong>Runtime extensibility</strong> - add custom algorithms or backends without new classes.
/// </description></item>
/// <item><description>
/// <strong>Separation of concerns</strong> - material storage, algorithm identity, and
/// cryptographic implementation are decoupled.
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Design Rationale: Extensible Type-Safe Identifiers</strong>
/// </para>
/// <para>
/// This type follows a "dynamic enum" pattern used throughout the Context namespace.
/// Regular C# enums cannot be extended by library users without forking. This pattern
/// provides type safety while allowing runtime extension:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Type safety</strong> - stronger than raw int or string identifiers.
/// </description></item>
/// <item><description>
/// <strong>Fast routing</strong> - integer comparison for registry lookups.
/// </description></item>
/// <item><description>
/// <strong>Extensibility</strong> - library users call <see cref="Create"/> to add custom values
/// at application startup for organization-specific backends.
/// </description></item>
/// </list>
/// <para>
/// <strong>Extending with Custom Values</strong>
/// </para>
/// <para>
/// To add custom values, call <see cref="Create"/> during application initialization.
/// Use code values above 1000 to avoid collisions with future library additions:
/// </para>
/// <code>
/// // Application startup
/// public static class CustomMaterialSemantics
/// {
///     public static MaterialSemantics AwsKmsReference { get; } = MaterialSemantics.Create(1001);
///     public static MaterialSemantics AzureKeyVaultReference { get; } = MaterialSemantics.Create(1002);
/// }
/// </code>
/// <para>
/// <strong>Thread Safety</strong>
/// </para>
/// <para>
/// The <see cref="Create"/> method is not thread-safe. Call it only during
/// application startup before concurrent access begins, such as in static
/// initializers or early in <c>Program.cs</c>. Predefined values are immutable
/// and safe for concurrent read access.
/// </para>
/// 
/// <para>
/// <strong>What This Type Represents</strong>
/// </para>
/// <para>
/// <see cref="MaterialSemantics"/> specifically describes how to interpret the bytes:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Direct material</strong> - the bytes ARE the cryptographic key material.
/// Software implementations (BouncyCastle, NSec, Microsoft) operate on these bytes directly.
/// </description></item>
/// <item><description>
/// <strong>Handle/reference</strong> - the bytes identify a key stored elsewhere.
/// The bound function interprets the handle and delegates operations to the appropriate backend
/// (TPM, HSM, cloud KMS, browser Web Crypto via WASM).
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Routing and Binding</strong>
/// </para>
/// <para>
/// When the <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> resolves
/// which function to bind, it uses <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/>
/// as primary discriminators. <see cref="MaterialSemantics"/> can serve as an additional
/// discriminator (via the qualifier parameter) to route to the correct backend:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>Direct</c> + <c>P256</c> + <c>Signing</c> → software ECDSA function.
/// </description></item>
/// <item><description>
/// <c>TpmHandle</c> + <c>P256</c> + <c>Signing</c> → TPM signing function.
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Separation of Concerns</strong>
/// </para>
/// <para>
/// This discriminator is distinct from:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Key identification</strong> - determining which key to use (kid, verification method ID).
/// </description></item>
/// <item><description>
/// <strong>Key storage/loading</strong> - where to fetch bytes from (database, file, API).
/// </description></item>
/// </list>
/// <para>
/// <see cref="MaterialSemantics"/> only describes what the loaded bytes represent,
/// enabling correct function binding regardless of where the bytes came from.
/// </para>
/// </remarks>
/// <seealso cref="SensitiveMemory"/>
/// <seealso cref="Tag"/>
/// <seealso cref="CryptoAlgorithm"/>
/// <seealso cref="Purpose"/>
/// <seealso cref="EncodingScheme"/>
/// <seealso cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
[DebuggerDisplay("{MaterialSemanticsNames.GetName(this),nq}")]
public readonly struct MaterialSemantics: IEquatable<MaterialSemantics>
{
    /// <summary>
    /// Gets the numeric code for this material semantics.
    /// </summary>
    public int Code { get; }


    private MaterialSemantics(int code)
    {
        Code = code;
    }


    /// <summary>
    /// Bytes are the actual cryptographic material. Functions operate on them directly.
    /// </summary>
    /// <remarks>
    /// Use this for software-based cryptographic operations where the key material
    /// resides in memory and is processed by managed or native crypto libraries
    /// (BouncyCastle, NSec, Microsoft platform crypto).
    /// </remarks>
    public static MaterialSemantics Direct { get; } = new(0);


    /// <summary>
    /// Bytes represent a TPM (Trusted Platform Module) handle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The bytes contain handle information that the TPM implementation understands.
    /// The bound cryptographic function delegates signing/verification operations
    /// to the TPM, which holds the actual key material in protected hardware.
    /// </para>
    /// <para>
    /// The key material never leaves the TPM; only the handle traverses the system.
    /// </para>
    /// </remarks>
    public static MaterialSemantics TpmHandle { get; } = new(1);


    private static readonly List<MaterialSemantics> semantics = new([Direct, TpmHandle]);


    /// <summary>
    /// Gets all registered material semantics values.
    /// </summary>
    public static IReadOnlyList<MaterialSemantics> Semantics => semantics.AsReadOnly();


    /// <summary>
    /// Creates a new material semantics value for custom backends.
    /// </summary>
    /// <param name="code">The unique numeric code for this semantics.</param>
    /// <returns>The newly created material semantics.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup,
    /// such as in static initializers or early in <c>Program.cs</c>.
    /// Use code values above 1000 to avoid collisions with future library additions.
    /// </para>
    /// </remarks>
    public static MaterialSemantics Create(int code)
    {
        for(int i = 0; i < semantics.Count; ++i)
        {
            if(semantics[i].Code == code)
            {
                throw new ArgumentException("Code already exists.");
            }
        }

        var newSemantics = new MaterialSemantics(code);
        semantics.Add(newSemantics);

        return newSemantics;
    }


    /// <inheritdoc />
    public override string ToString() => MaterialSemanticsNames.GetName(this);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(MaterialSemantics other)
    {
        return Code == other.Code;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is MaterialSemantics other && Equals(other);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in MaterialSemantics left, in MaterialSemantics right)
    {
        return left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in MaterialSemantics left, in MaterialSemantics right)
    {
        return !left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object left, in MaterialSemantics right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in MaterialSemantics left, in object right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object left, in MaterialSemantics right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in MaterialSemantics left, in object right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return Code;
    }
}


/// <summary>
/// Provides human-readable names for <see cref="MaterialSemantics"/> values.
/// </summary>
public static class MaterialSemanticsNames
{
    /// <summary>
    /// Gets the name for the specified material semantics.
    /// </summary>
    /// <param name="semantics">The material semantics.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(MaterialSemantics semantics)
    {
        return GetName(semantics.Code);
    }


    /// <summary>
    /// Gets the name for the specified material semantics code.
    /// </summary>
    /// <param name="code">The numeric code.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(int code)
    {
        return code switch
        {
            var c when c == MaterialSemantics.Direct.Code => nameof(MaterialSemantics.Direct),
            var c when c == MaterialSemantics.TpmHandle.Code => nameof(MaterialSemantics.TpmHandle),
            _ => $"Custom: ('{code}')."
        };
    }
}