using System.Buffers;

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
