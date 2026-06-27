using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm;

/// <summary>
/// Adapts a TPM-resident signing key to the <see cref="SigningDelegate"/> shape used by
/// <see cref="Verifiable.Cryptography.PrivateKey"/> and the rest of the library. The key material never leaves
/// the TPM: the bytes the delegate receives are the key's <b>handle</b>, not a secret, and the actual signing
/// is delegated to <c>TPM2_Sign</c>. This is the hardware-bound counterpart of the software backends
/// (<c>MicrosoftCryptographicFunctions</c>, <c>NSecCryptographicFunctions</c>).
/// </summary>
/// <remarks>
/// <para>
/// Per-call state — the <see cref="TpmDevice"/>, the TPM signing scheme, and the hash algorithm — is supplied
/// through the delegate's <c>context</c> dictionary rather than captured in a closure, so the function stays a
/// plain static <see cref="SigningDelegate"/>. Build the context with
/// <see cref="CreateP256SigningContext(TpmDevice)"/> (or assemble the <see cref="SchemeContextKey"/> and
/// related entries directly for other schemes), and carry the handle with
/// <see cref="CreateHandleKeyMemory(uint, Tag, MemoryPool{byte})"/>.
/// </para>
/// </remarks>
public static class TpmCryptographicFunctions
{
    /// <summary>The largest digest this function produces (SHA-512), used to size the stack hash buffer.</summary>
    private const int MaxDigestLength = 64;

    /// <summary>Context key: the <see cref="TpmDevice"/> the signing command is submitted to.</summary>
    public const string DeviceContextKey = "tpm.device";

    /// <summary>Context key: the TPM signing scheme as a <see cref="TpmAlgIdConstants"/> (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</summary>
    public const string SchemeContextKey = "tpm.scheme";

    /// <summary>Context key: the hash algorithm as a <see cref="TpmAlgIdConstants"/> (TPM_ALG_SHA256/384/512).</summary>
    public const string HashContextKey = "tpm.hash";

    /// <summary>Context key: for ECDSA, the fixed width in bytes of each of the r and s components (the curve order size); ignored for RSA.</summary>
    public const string EcdsaComponentSizeContextKey = "tpm.ecdsaComponentSize";

    /// <summary>Context key: the <see cref="Tag"/> to stamp on the produced <see cref="Signature"/>.</summary>
    public const string SignatureTagContextKey = "tpm.signatureTag";

    /// <summary>
    /// Builds a signing context for a NIST P-256 / ECDSA-SHA256 TPM key: ECDSA scheme, SHA-256 hash, 32-byte
    /// signature components, and the <see cref="CryptoTags.P256Signature"/> tag.
    /// </summary>
    /// <param name="device">The TPM device to submit signing commands to.</param>
    /// <returns>A context dictionary for <see cref="SignAsync"/>.</returns>
    public static FrozenDictionary<string, object> CreateP256SigningContext(TpmDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);

        var context = new Dictionary<string, object>(5)
        {
            [DeviceContextKey] = device,
            [SchemeContextKey] = TpmAlgIdConstants.TPM_ALG_ECDSA,
            [HashContextKey] = TpmAlgIdConstants.TPM_ALG_SHA256,
            [EcdsaComponentSizeContextKey] = 32,
            [SignatureTagContextKey] = CryptoTags.P256Signature
        };

        return context.ToFrozenDictionary();
    }

    /// <summary>
    /// Wraps a transient TPM object handle as private-key memory. The four big-endian handle bytes stand in for
    /// the key material a software backend would hold; <see cref="SignAsync"/> interprets them as a handle.
    /// </summary>
    /// <param name="handle">The loaded signing key's handle.</param>
    /// <param name="tag">The key tag (algorithm/purpose), for example <see cref="CryptoTags.P256PrivateKey"/>.</param>
    /// <param name="pool">The memory pool for the handle buffer.</param>
    /// <returns>Private-key memory carrying the handle.</returns>
    public static PrivateKeyMemory CreateHandleKeyMemory(uint handle, Tag tag, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(sizeof(uint));
        BinaryPrimitives.WriteUInt32BigEndian(owner.Memory.Span, handle);

        return new PrivateKeyMemory(owner, tag);
    }

    /// <summary>
    /// Signs <paramref name="dataToSign"/> with a TPM-resident key, matching <see cref="SigningDelegate"/>.
    /// </summary>
    /// <param name="handleBytes">The four big-endian bytes of the TPM key handle (not a secret).</param>
    /// <param name="dataToSign">The message to sign; it is hashed with the context's hash algorithm before TPM2_Sign.</param>
    /// <param name="signaturePool">The pool for the returned signature buffer.</param>
    /// <param name="context">Per-call state — see the context-key constants; must not be <see langword="null"/>.</param>
    /// <param name="cancellationToken">A token observed across the signing exchange.</param>
    /// <returns>The signature: ECDSA as IEEE P1363 (r || s), RSA as the raw signature octets.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned Signature transfers to the caller.")]
    public static async ValueTask<Signature> SignAsync(
        ReadOnlyMemory<byte> handleBytes,
        ReadOnlyMemory<byte> dataToSign,
        MemoryPool<byte> signaturePool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signaturePool);
        ArgumentNullException.ThrowIfNull(context);

        var device = (TpmDevice)context[DeviceContextKey];
        var scheme = (TpmAlgIdConstants)context[SchemeContextKey];
        var hash = (TpmAlgIdConstants)context[HashContextKey];
        var signatureTag = (Tag)context[SignatureTagContextKey];

        uint handle = BinaryPrimitives.ReadUInt32BigEndian(handleBytes.Span);

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        //Hashing happens in a synchronous helper so the stack digest buffer never crosses an await.
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(signaturePool);
        using SignInput signInput = BuildSignInput(handle, dataToSign.Span, scheme, hash, signaturePool);

        TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            device, signInput, [keyAuth], null, signaturePool, registry, cancellationToken).ConfigureAwait(false);

        if(!result.IsSuccess)
        {
            throw new InvalidOperationException($"TPM2_Sign failed with response code '{result.ResponseCode}'.");
        }

        using SignResponse response = result.Value;

        //ECDSA needs the curve order size to lay out the IEEE P1363 components; RSA ignores it. The projection
        //into the neutral Signature carrier is shared with TPM attestation (see TpmCryptographicProjections).
        int ecdsaComponentSize = scheme == TpmAlgIdConstants.TPM_ALG_ECDSA ? (int)context[EcdsaComponentSizeContextKey] : 0;

        return response.Signature.ToSignature(ecdsaComponentSize, signatureTag, signaturePool);
    }

    /// <summary>
    /// Hashes <paramref name="message"/> on the stack and builds the matching <see cref="SignInput"/>; kept
    /// synchronous so the stack digest span never spans an <c>await</c>. <see cref="SignInput"/> copies the
    /// digest into pooled memory it owns.
    /// </summary>
    /// <param name="handle">The signing key handle.</param>
    /// <param name="message">The message to hash and sign.</param>
    /// <param name="scheme">The TPM signing scheme.</param>
    /// <param name="hash">The hash algorithm.</param>
    /// <param name="pool">The memory pool for the command's buffers.</param>
    /// <returns>A configured <see cref="SignInput"/>.</returns>
    private static SignInput BuildSignInput(uint handle, ReadOnlySpan<byte> message, TpmAlgIdConstants scheme, TpmAlgIdConstants hash, MemoryPool<byte> pool)
    {
        //Hash into a pooled buffer (cleared on release) rather than the stack, so transient crypto material has
        //a uniform containment story; SignInput copies the digest into its own pooled buffer.
        using IMemoryOwner<byte> digestOwner = pool.Rent(MaxDigestLength);
        Span<byte> digestBuffer = digestOwner.Memory.Span;
        int digestLength = ComputeDigest(message, hash, digestBuffer);
        ReadOnlySpan<byte> digest = digestBuffer[..digestLength];
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(handle);

        SignInput input = scheme switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => SignInput.ForEcdsa(keyHandle, digest, hash, pool),
            TpmAlgIdConstants.TPM_ALG_RSASSA => SignInput.ForRsaSsa(keyHandle, digest, hash, pool),
            TpmAlgIdConstants.TPM_ALG_RSAPSS => SignInput.ForRsaPss(keyHandle, digest, hash, pool),
            _ => throw new NotSupportedException($"Signing scheme '{scheme}' is not supported by the TPM signing function.")
        };

        digestBuffer.Clear();

        return input;
    }

    /// <summary>
    /// Hashes a message into <paramref name="destination"/> with the hash algorithm named by a
    /// <see cref="TpmAlgIdConstants"/> value.
    /// </summary>
    /// <param name="data">The message bytes.</param>
    /// <param name="hash">The TPM hash algorithm identifier.</param>
    /// <param name="destination">The buffer that receives the digest; must be at least the digest size.</param>
    /// <returns>The number of digest bytes written.</returns>
    private static int ComputeDigest(ReadOnlySpan<byte> data, TpmAlgIdConstants hash, Span<byte> destination) => hash switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA256 => SHA256.HashData(data, destination),
        TpmAlgIdConstants.TPM_ALG_SHA384 => SHA384.HashData(data, destination),
        TpmAlgIdConstants.TPM_ALG_SHA512 => SHA512.HashData(data, destination),
        _ => throw new NotSupportedException($"Hash algorithm '{hash}' is not supported by the TPM signing function.")
    };
}
