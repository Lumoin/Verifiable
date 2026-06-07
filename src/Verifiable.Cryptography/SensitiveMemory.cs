using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

// This library provides two parallel sets of cryptographic function delegates:
//
// +------------------------------------------------------------------+
// |                  Bound Key Delegates (this file)                 |
// +------------------------------------------------------------------+
// | SigningFunction<T>, VerificationFunction<T>:                     |
// | - Use ReadOnlyMemory<byte> for async safety.                     |
// | - Can be stored in PublicKey/PrivateKey objects.                 |
// | - Generic type parameters for flexibility.                       |
// | - Used by: PublicKey.VerifyAsync, PrivateKey.SignAsync.          |
// +------------------------------------------------------------------+
//
// +------------------------------------------------------------------+
// |              Registry Delegates (CryptoFunctionRegistry.cs)      |
// +------------------------------------------------------------------+
// | SigningDelegate, VerificationDelegate:                           |
// | - Use ReadOnlySpan<byte> for zero-allocation dispatch.           |
// | - Cannot be stored (span is stack-only).                         |
// | - Include FrozenDictionary context parameter.                    |
// | - Used by: Jws.SignAsync, CredentialJwsExtensions.               |
// +------------------------------------------------------------------+
//
// Why Two Sets?
//
// - Registry pattern resolves a function at call time, invokes it immediately,
//   and discards it. ReadOnlySpan enables zero-allocation access to key bytes
//   but cannot cross await boundaries or be stored in fields.
//
// - Bound key pattern stores a function inside a PublicKey or PrivateKey object
//   for repeated use. ReadOnlyMemory can be stored and passed across async
//   boundaries.
//
// The CryptographicKeyFactory bridges these patterns by resolving functions
// and combining them with key material to create ready-to-use key objects.
//


/// <summary>
/// Verification function for bound key objects using <see cref="Signature"/> type.
/// </summary>
/// <typeparam name="TVerificationContext">The type of public key bytes. Typically <see cref="byte"/>.</typeparam>
/// <typeparam name="TDataToVerify">The type of data to verify. Typically <see cref="byte"/>.</typeparam>
/// <typeparam name="TSignature">The signature type. Typically <see cref="Signature"/>.</typeparam>
/// <typeparam name="TResult">The result type. Typically <see cref="bool"/> or <see cref="ValueTask{Boolean}"/>.</typeparam>
/// <param name="publicKeyBytes">The public key bytes.</param>
/// <param name="dataToVerify">The data that was signed.</param>
/// <param name="signature">The signature to verify.</param>
/// <returns>The verification result.</returns>
/// <remarks>
/// <para>
/// This delegate uses <see cref="ReadOnlyMemory{T}"/> rather than <see cref="ReadOnlySpan{T}"/>
/// because it is stored inside <see cref="PublicKey"/> objects and must be usable across
/// <c>await</c> boundaries. For the span-based registry pattern, see <c>VerificationDelegate</c>
/// in <c>CryptoFunctionRegistry.cs</c>.
/// </para>
/// </remarks>
/// <seealso cref="PublicKey"/>
/// <seealso cref="VerificationFunctionWithBytes{TPublicKeyBytes, TDataToVerify, TSignatureBytes, TResult}"/>
public delegate TResult VerificationFunction<TVerificationContext, TDataToVerify, in TSignature, out TResult>(
    ReadOnlyMemory<TVerificationContext> publicKeyBytes,
    ReadOnlyMemory<TDataToVerify> dataToVerify,
    TSignature signature);


/// <summary>
/// Verification function for bound key objects using raw signature bytes.
/// </summary>
/// <typeparam name="TPublicKeyBytes">The type of public key bytes. Typically <see cref="byte"/>.</typeparam>
/// <typeparam name="TDataToVerify">The type of data to verify. Typically <see cref="byte"/>.</typeparam>
/// <typeparam name="TSignatureBytes">The type of signature bytes. Typically <see cref="byte"/>.</typeparam>
/// <typeparam name="TResult">The result type. Typically <see cref="bool"/>.</typeparam>
/// <param name="publicKeyBytes">The public key bytes.</param>
/// <param name="dataToVerify">The data that was signed.</param>
/// <param name="signatureBytes">The raw signature bytes.</param>
/// <returns>The verification result.</returns>
/// <remarks>
/// <para>
/// This variant accepts raw signature bytes as <see cref="ReadOnlyMemory{T}"/> instead of a
/// <see cref="Signature"/> object. Use this when the signature is already available as bytes
/// without needing to wrap it in a <see cref="Signature"/> instance.
/// </para>
/// </remarks>
/// <seealso cref="VerificationFunction{TVerificationContext, TDataToVerify, TSignature, TResult}"/>
public delegate TResult VerificationFunctionWithBytes<TPublicKeyBytes, TDataToVerify, TSignatureBytes, out TResult>(
    ReadOnlyMemory<TPublicKeyBytes> publicKeyBytes,
    ReadOnlySpan<TDataToVerify> dataToVerify,
    ReadOnlyMemory<TSignatureBytes> signatureBytes);


/// <summary>
/// Signing function for bound key objects.
/// </summary>
/// <typeparam name="TPrivateKeyBytes">The type of private key bytes. Typically <see cref="byte"/>.</typeparam>
/// <typeparam name="TDataToSign">The type of data to sign. Typically <see cref="byte"/>.</typeparam>
/// <typeparam name="TResult">The result type. Typically <see cref="Signature"/> or <see cref="ValueTask{Signature}"/>.</typeparam>
/// <param name="privateKeyBytes">The private key bytes.</param>
/// <param name="dataToSign">The data to sign.</param>
/// <param name="signaturePool">Memory pool for allocating the signature buffer.</param>
/// <returns>The signing result, typically a <see cref="Signature"/>.</returns>
/// <remarks>
/// <para>
/// This delegate uses <see cref="ReadOnlyMemory{T}"/> rather than <see cref="ReadOnlySpan{T}"/>
/// because it is stored inside <see cref="PrivateKey"/> objects and must be usable across
/// <c>await</c> boundaries. For the span-based registry pattern, see <c>SigningDelegate</c>
/// in <c>CryptoFunctionRegistry.cs</c>.
/// </para>
/// </remarks>
/// <seealso cref="PrivateKey"/>
public delegate TResult SigningFunction<TPrivateKeyBytes, TDataToSign, out TResult>(
    ReadOnlyMemory<TPrivateKeyBytes> privateKeyBytes,
    ReadOnlyMemory<TDataToSign> dataToSign,
    MemoryPool<byte> signaturePool);


/// <summary>
/// Generic function that operates on a read-only span and returns a result.
/// </summary>
/// <typeparam name="T">The element type of the span.</typeparam>
/// <typeparam name="TResult">The result type.</typeparam>
/// <param name="input">The input span.</param>
/// <returns>The computed result.</returns>
public delegate TResult ReadOnlySpanFunc<T, out TResult>(ReadOnlySpan<T> input);


/// <summary>
/// Base class for sensitive data that carries metadata via <see cref="Tag"/>.
/// </summary>
public abstract class SensitiveData
{
    /// <summary>
    /// Gets the metadata tag describing this sensitive data.
    /// </summary>
    public Tag Tag { get; }


    /// <summary>
    /// Initializes a new instance with the specified tag.
    /// </summary>
    /// <param name="tag">Tags the data with out-of-band information such as algorithm and purpose.</param>
    protected SensitiveData(Tag tag)
    {
        ArgumentNullException.ThrowIfNull(tag, nameof(tag));
        Tag = tag;
    }
}


/// <summary>
/// Base class for memory containing cryptographic material or key references.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Architecture Overview</strong>
/// </para>
/// <para>
/// This class is the foundation of a layered cryptographic key hierarchy designed to support
/// multiple backends (software, TPM, HSM, cloud KMS, browser Web Crypto) through a unified API.
/// </para>
/// <para>
/// <strong>OpenTelemetry Lifetime Spans</strong>
/// </para>
/// <para>
/// When an <see cref="Activity"/> is supplied at construction, this class manages
/// its lifetime — stopping it in <see cref="Dispose(bool)"/> and tagging it with
/// <c>crypto.lifetime_ms</c> at that point. Backends start the activity before
/// construction and stamp it with provenance attributes (<c>crypto.provider.library</c>,
/// <c>crypto.provider.version</c>, <c>crypto.library.name</c>,
/// <c>crypto.library.version</c>, <c>crypto.provider.class</c>,
/// <c>crypto.provider.operation</c>, <c>crypto.byte_length</c>).
/// </para>
/// <para>
/// If no OTel listener is configured, <see cref="ActivitySource.StartActivity"/> returns
/// <see langword="null"/> and the <c>activity</c> parameter should be passed as
/// <see langword="null"/>. The constructor accepts <see langword="null"/> and the
/// entire path is zero-cost.
/// </para>
/// <para>
/// Subscribe to lifetime spans at application startup:
/// </para>
/// <code>
/// using var tracerProvider = Sdk.CreateTracerProviderBuilder()
///     .AddSource(CryptoActivitySource.Name)
///     .AddOtlpExporter()
///     .Build();
/// </code>
/// <para>
/// <strong>CBOM Provenance</strong>
/// </para>
/// <para>
/// The <see cref="Tag"/> on every instance carries <see cref="ProviderLibrary"/>,
/// <see cref="CryptoLibrary"/>, <see cref="ProviderClass"/>, and
/// <see cref="ProviderOperation"/> entries stamped by the backend at construction.
/// These entries survive for the full lifetime of the value and are accessible
/// to any code holding a reference — no event subscription required.
/// </para>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="CryptoActivitySource"/>
/// <seealso cref="ProviderLibrary"/>
/// <seealso cref="CryptoLibrary"/>
public abstract class SensitiveMemory: SensitiveData, IDisposable, IEquatable<SensitiveMemory>
{
    private bool disposed;
    private readonly Activity? lifetime;

    /// <summary>
    /// The piece of sensitive data.
    /// </summary>
    protected IMemoryOwner<byte> MemoryOwner { get; }


    /// <summary>
    /// Initializes a new instance of <see cref="SensitiveMemory"/>.
    /// </summary>
    /// <param name="sensitiveMemory">
    /// The memory owner holding the sensitive bytes. Ownership transfers to this instance.
    /// </param>
    /// <param name="tag">
    /// Metadata describing the contents — algorithm, purpose, encoding, and provenance.
    /// Backends stamp <see cref="ProviderLibrary"/>, <see cref="CryptoLibrary"/>,
    /// <see cref="ProviderClass"/>, and <see cref="ProviderOperation"/> entries here
    /// for CBOM traceability.
    /// </param>
    /// <param name="lifetime">
    /// An optional OTel <see cref="Activity"/> spanning the lifetime of this value.
    /// Started by the backend before construction; stopped by <see cref="Dispose()"/>.
    /// Pass <see langword="null"/> when no OTel listener is active — the constructor
    /// is zero-cost in that case.
    /// </param>
    protected SensitiveMemory(
        IMemoryOwner<byte> sensitiveMemory,
        Tag tag,
        Activity? lifetime = null) : base(tag)
    {
        ArgumentNullException.ThrowIfNull(sensitiveMemory);
        MemoryOwner = sensitiveMemory;
        this.lifetime = lifetime;
    }


    /// <summary>
    /// Exposes the internal sensitive memory as a read-only span.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return MemoryOwner.Memory.Span;
    }


    /// <summary>
    /// Exposes the internal sensitive memory as read-only memory.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    public ReadOnlyMemory<byte> AsReadOnlyMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return MemoryOwner.Memory;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Releases resources held by this instance and stops the OTel lifetime span
    /// if one was supplied at construction.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/> if called from <see cref="Dispose()"/>;
    /// <see langword="false"/> if called from a finalizer.
    /// </param>
    protected virtual void Dispose(bool disposing)
    {
        if(disposed)
        {
            return;
        }

        //Shared empty instances backed by EmptyMemoryOwner are singletons
        //that must never be disposed. Their Dispose is a no-op, but setting
        //the disposed flag would poison all future users of the singleton.
        if(MemoryOwner is EmptyMemoryOwner)
        {
            return;
        }

        if(disposing)
        {
            //Clearing the memory is in case there is not a pooled memory owner
            //that clears it. One example is Verifiable.Core.ExactSizeMemoryPool.
            MemoryOwner.Memory.Span.Clear();
            MemoryOwner.Dispose();

            if(lifetime is not null)
            {
                lifetime.Stop();
                lifetime.SetTag(CryptoTelemetry.LifetimeMs,
                    lifetime.Duration.TotalMilliseconds);
            }
        }

        disposed = true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] SensitiveMemory? other)
    {
        return other is not null
            && MemoryExtensions.SequenceEqual(
                MemoryOwner.Memory.Span,
                other.MemoryOwner.Memory.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is SensitiveMemory s && Equals(s);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in SensitiveMemory s1, in SensitiveMemory s2) => Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in SensitiveMemory s1, in SensitiveMemory s2) => !Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object s1, in SensitiveMemory s2) => Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in SensitiveMemory s1, in object s2) => Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object s1, in SensitiveMemory s2) => !Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in SensitiveMemory s1, in object s2) => !Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        ReadOnlySpan<byte> memorySpan = MemoryOwner.Memory.Span;
        for(int i = 0; i < memorySpan.Length; ++i)
        {
            hash.Add(memorySpan[i].GetHashCode());
        }

        return hash.ToHashCode();
    }
}