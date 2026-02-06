using System.Buffers;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Context;

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
/// <para>
/// The <paramref name="dataToVerify"/> parameter uses <see cref="ReadOnlySpan{T}"/> for efficiency
/// when the data is consumed immediately without storage.
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
/// <para>
/// The returned signature should be allocated from <paramref name="signaturePool"/>. The caller
/// is responsible for disposing the returned memory.
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
/// <remarks>
/// <para>
/// This is a general-purpose delegate for operations that consume span data synchronously.
/// It cannot be stored or used across <c>await</c> boundaries due to the span parameter.
/// </para>
/// </remarks>
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
/// Data flows through with minimal state; wrapping is optional convenience, not required.
/// </para>
/// 
/// <para>
/// <strong>Type Hierarchy</strong>
/// </para>
/// <code>
/// SensitiveMemory                     IMemoryOwner&lt;byte&gt; + Tag
///     |
///     +-- PublicKeyMemory             Typed wrapper with WithKeyBytesAsync
///     |       |
///     |       +-- PublicKey           Memory + bound VerificationFunction + KeyId
///     |
///     +-- PrivateKeyMemory            Typed wrapper with WithKeyBytesAsync
///     |       |
///     |       +-- PrivateKey          Memory + bound SigningFunction + KeyId
///     |
///     +-- Signature                   Sealed. Output of signing operations.
/// </code>
/// <para>
/// All cryptographic material in this library is tracked through this hierarchy.
/// There are no naked, opaque byte buffers. Every piece of sensitive memory carries
/// a <see cref="Tag"/> describing what it is (algorithm, purpose, encoding, semantics),
/// is disposable to ensure cleanup, and is guarded against use-after-dispose.
/// </para>
/// 
/// <para>
/// <strong>Memory Contents: Material vs Handle</strong>
/// </para>
/// <para>
/// The bytes in this memory can represent different things, indicated by
/// <see cref="MaterialSemantics"/> in the <see cref="Tag"/>:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Direct material (<see cref="MaterialSemantics.Direct"/>)</strong> - 
/// The bytes ARE the cryptographic key material. Software implementations
/// (BouncyCastle, NSec, Microsoft platform crypto) operate on these bytes directly.
/// </description></item>
/// <item><description>
/// <strong>Handle/reference (<see cref="MaterialSemantics.TpmHandle"/> etc.)</strong> - 
/// The bytes identify a key stored in secure hardware or remote service.
/// The bound cryptographic function interprets the handle and delegates operations
/// to the appropriate backend. The actual key material never leaves the secure boundary.
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Three-Step Key Resolution</strong>
/// </para>
/// <para>
/// Using cryptographic keys involves three distinct concerns:
/// </para>
/// <code>
/// +---------------------------------------------------------------------+
/// | 1. IDENTIFICATION                                                   |
/// |    "Which key?"                                                     |
/// |    -----------------------------------------------------------------|
/// |    Inputs: kid header, verification method ID, issuer config        |
/// |    Output: Key identifier / reference                               |
/// +---------------------------------------------------------------------+
///                                    |
///                                    v
/// +---------------------------------------------------------------------+
/// | 2. LOADING                                                          |
/// |    "Fetch bytes and metadata from storage"                          |
/// |    -----------------------------------------------------------------|
/// |    Sources: Database, file, API, in-memory cache                    |
/// |    Output: Bytes + Tag (algorithm, purpose, semantics)              |
/// |    Creates: PublicKeyMemory or PrivateKeyMemory                     |
/// +---------------------------------------------------------------------+
///                                    |
///                                    v
/// +---------------------------------------------------------------------+
/// | 3. BINDING                                                          |
/// |    "Attach appropriate cryptographic function"                      |
/// |    -----------------------------------------------------------------|
/// |    Uses: Tag to route via CryptoFunctionRegistry                    |
/// |    Output: PublicKey or PrivateKey with bound function              |
/// |    Ready for: SignAsync, VerifyAsync operations                     |
/// +---------------------------------------------------------------------+
/// </code>
/// 
/// <para>
/// <strong>Function Binding Patterns</strong>
/// </para>
/// <para>
/// Cryptographic operations are performed by delegate functions. Three patterns are supported:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Explicit function</strong> - Caller passes the function directly.
/// Maximum flexibility, no registry needed. Used in tests and specialized scenarios.
/// </description></item>
/// <item><description>
/// <strong>Registry-based</strong> - Function resolved from
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> based on
/// <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/> from the key's <see cref="Tag"/>.
/// </description></item>
/// <item><description>
/// <strong>Resolver/Binder</strong> - Uses <c>KeyMaterialResolver</c> and <c>KeyMaterialBinder</c>
/// delegates for complex scenarios like DID resolution or database-backed key storage.
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Why This Design?</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Source agnosticism</strong> - Key material can come from any storage.
/// The loading step is completely user-defined.
/// </description></item>
/// <item><description>
/// <strong>Implementation flexibility</strong> - Swap backends (BouncyCastle to NSec to Microsoft)
/// without changing key storage or application code.
/// </description></item>
/// <item><description>
/// <strong>Dynamic routing</strong> - Different operations can use different backends.
/// Use FIPS-certified hardware for regulated operations, fast software for others.
/// </description></item>
/// <item><description>
/// <strong>Testability</strong> - Substitute implementations in tests without mocking.
/// </description></item>
/// <item><description>
/// <strong>Regulatory compliance</strong> - Move to HSM/TPM when regulations require,
/// storage schema unchanged.
/// </description></item>
/// <item><description>
/// <strong>Gradual migration</strong> - Move keys to secure hardware incrementally
/// by updating <see cref="MaterialSemantics"/> and binding.
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Security Considerations</strong>
/// </para>
/// <para>
/// Sensitive data may be present in crash dumps, page files, or temporary variables.
/// When possible, security-sensitive operations should be done on locked systems
/// with restricted privileges. The <see cref="Dispose"/> method clears memory contents.
/// For hardware-backed keys (<see cref="MaterialSemantics.TpmHandle"/>), the actual
/// key material never enters process memory. Accessing memory after disposal throws
/// <see cref="ObjectDisposedException"/> to guard against use-after-free bugs.
/// </para>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="PublicKeyMemory"/>
/// <seealso cref="PrivateKeyMemory"/>
/// <seealso cref="Signature"/>
/// <seealso cref="PublicKey"/>
/// <seealso cref="PrivateKey"/>
/// <seealso cref="MaterialSemantics"/>
/// <seealso cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// <seealso cref="CryptographicKeyFactory"/>
public abstract class SensitiveMemory: SensitiveData, IDisposable, IEquatable<SensitiveMemory>
{
    /// <summary>
    /// Detects and prevents redundant dispose calls.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// The piece of sensitive data.
    /// </summary>
    protected IMemoryOwner<byte> MemoryOwner { get; }


    /// <summary>
    /// Sensitive memory default constructor.
    /// </summary>
    /// <param name="sensitiveMemory">The piece of sensitive memory that is wrapped and owned.</param>
    /// <param name="tag">Tags the memory with out-of-band information such as key material information.</param>
    protected SensitiveMemory(IMemoryOwner<byte> sensitiveMemory, Tag tag) : base(tag)
    {
        ArgumentNullException.ThrowIfNull(sensitiveMemory);
        this.MemoryOwner = sensitiveMemory;
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


    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Allows inherited resources to hook into application defined tasks with freeing,
    /// releasing, or resetting unmanaged resources.
    /// </summary>
    /// <param name="disposing"><see langword="true"/> if called from <see cref="Dispose()"/>; <see langword="false"/> if called from a finalizer.</param>
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
            MemoryOwner?.Dispose();
        }

        disposed = true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] SensitiveMemory? other)
    {
        //The reason for this is that Memory<T> does not implement deep hashing
        //due to performance concerns.
        return other is not null
            && MemoryExtensions.SequenceEqual(MemoryOwner.Memory.Span, other.MemoryOwner.Memory.Span);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => (obj is SensitiveMemory s) && Equals(s);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in SensitiveMemory s1, in SensitiveMemory s2) => Equals(s1, s2);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in SensitiveMemory s1, in SensitiveMemory s2) => !Equals(s1, s2);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object s1, in SensitiveMemory s2) => Equals(s1, s2);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in SensitiveMemory s1, in object s2) => Equals(s1, s2);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object s1, in SensitiveMemory s2) => !Equals(s1, s2);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in SensitiveMemory s1, in object s2) => !Equals(s1, s2);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        //The reason for this is that Memory<T> does not implement deep hashing
        //due to performance concerns.
        var hash = new HashCode();
        ReadOnlySpan<byte> memorySpan = MemoryOwner.Memory.Span;
        for(int i = 0; i < memorySpan.Length; ++i)
        {
            hash.Add(memorySpan[i].GetHashCode());
        }

        return hash.ToHashCode();
    }
}