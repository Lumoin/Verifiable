using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm;

/// <summary>
/// Adapts a TPM-resident signing key to the <see cref="SigningDelegate"/> shape used by
/// <see cref="Verifiable.Cryptography.PrivateKey"/> and the rest of the library. The key material never leaves
/// the TPM: the bytes the delegate receives are the key's <b>handle</b>, not a secret, and the actual signing
/// is delegated to <c>TPM2_Sign</c>. This is the hardware-bound counterpart of the software backends
/// (<c>MicrosoftCryptographicFunctions</c>, <c>LibsodiumCryptographicFunctions</c>).
/// </summary>
/// <remarks>
/// <para>
/// Per-call state — the <see cref="TpmDevice"/>, the TPM signing scheme, and the hash algorithm — is supplied
/// through the delegate's <c>context</c> dictionary rather than captured in a closure, so the function stays a
/// plain static <see cref="SigningDelegate"/>. Build the context with
/// <see cref="CreateP256SigningContext(TpmDevice)"/> (or assemble the <see cref="SchemeContextKey"/> and
/// related entries directly for other schemes), and carry the handle with
/// <see cref="CreateHandleKeyMemory(uint, Tag, BaseMemoryPool)"/>.
/// </para>
/// </remarks>
public static class TpmCryptographicFunctions
{
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
    public static PrivateKeyMemory CreateHandleKeyMemory(uint handle, Tag tag, BaseMemoryPool pool)
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
    /// <summary>The backend name stamped on the <see cref="SignatureProducedEvent"/> this function emits.</summary>
    private const string BackendName = "Tpm";


    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned Signature transfers to the caller.")]
    public static async ValueTask<(Signature Signature, CryptoEvent? Event)> SignAsync(
        ReadOnlyMemory<byte> handleBytes,
        ReadOnlyMemory<byte> dataToSign,
        BaseMemoryPool signaturePool,
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

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(signaturePool);

        //The pre-hash routes through the registered async digest seam (this method is already async, so the
        //seam is reachable with no sync-over-async bridge) rather than a direct framework hash call, matching
        //this assembly's own TpmCommandExecutor/TpmSimulator/TpmLifecycleTransitions digest sites.
        int digestLength = GetDigestSize(hash);
        using IMemoryOwner<byte> digestOwner = signaturePool.Rent(digestLength);
        Memory<byte> digestBuffer = digestOwner.Memory[..digestLength];
        await ComputeDigestAsync(dataToSign, hash, digestBuffer, signaturePool, cancellationToken).ConfigureAwait(false);

        //SignInput copies the digest into its own pooled buffer; the temporary one is cleared once that copy
        //is made, matching the project's uniform containment story for transient crypto material.
        using SignInput signInput = BuildSignInput(handle, digestBuffer.Span, scheme, hash, signaturePool);
        digestBuffer.Span.Clear();

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

        Signature signatureResult = response.Signature.ToSignature(ecdsaComponentSize, signatureTag, signaturePool);
        CryptoEvent evt = SignatureProducedEvent.Create(
            signatureTag.Get<Verifiable.Cryptography.Context.CryptoAlgorithm>(), dataToSign.Length, signatureResult.AsReadOnlyMemory().Length, BackendName);

        return (signatureResult, evt);
    }

    /// <summary>
    /// Builds the <see cref="SignInput"/> around an already-computed <paramref name="digest"/>.
    /// <see cref="SignInput"/> copies the digest into pooled memory it owns; the caller
    /// (<see cref="SignAsync"/>) is responsible for clearing its own temporary digest buffer once this
    /// returns.
    /// </summary>
    /// <param name="handle">The signing key handle.</param>
    /// <param name="digest">The pre-computed message digest.</param>
    /// <param name="scheme">The TPM signing scheme.</param>
    /// <param name="hash">The hash algorithm the digest was computed under.</param>
    /// <param name="pool">The memory pool for the command's buffers.</param>
    /// <returns>A configured <see cref="SignInput"/>.</returns>
    private static SignInput BuildSignInput(uint handle, ReadOnlySpan<byte> digest, TpmAlgIdConstants scheme, TpmAlgIdConstants hash, BaseMemoryPool pool)
    {
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(handle);

        return scheme switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => SignInput.ForEcdsa(keyHandle, digest, hash, pool),
            TpmAlgIdConstants.TPM_ALG_RSASSA => SignInput.ForRsaSsa(keyHandle, digest, hash, pool),
            TpmAlgIdConstants.TPM_ALG_RSAPSS => SignInput.ForRsaPss(keyHandle, digest, hash, pool),
            _ => throw new NotSupportedException($"Signing scheme '{scheme}' is not supported by the TPM signing function.")
        };
    }

    /// <summary>
    /// Hashes <paramref name="message"/> through the registered async digest seam
    /// (<see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>)
    /// into <paramref name="destination"/>, rather than a direct framework hash call — this TPM host-side
    /// pre-hash before <c>TPM2_Sign</c> is exactly the kind of trust/custody digest the async seam exists
    /// for (it may be TPM2_Hash- or KMS-backed), matching this assembly's own
    /// <see cref="Infrastructure.TpmCommandExecutor"/>/<c>TpmSimulator</c>/<c>TpmLifecycleTransitions</c>
    /// digest sites.
    /// </summary>
    /// <param name="message">The message bytes.</param>
    /// <param name="hash">The TPM hash algorithm identifier.</param>
    /// <param name="destination">The buffer that receives the digest; must be exactly the digest size.</param>
    /// <param name="pool">The memory pool the digest computation rents pooled buffers from.</param>
    /// <param name="cancellationToken">A token observed while awaiting the digest.</param>
    private static async ValueTask ComputeDigestAsync(
        ReadOnlyMemory<byte> message, TpmAlgIdConstants hash, Memory<byte> destination, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag tag = BuildDigestTag(hash);
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, destination.Length, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        //The pooled digest buffer may be larger than the requested length (pool implementations are free to
        //over-allocate); slice to the exact requested size before copying into the caller's destination.
        digest.AsReadOnlySpan()[..destination.Length].CopyTo(destination.Span);
    }

    /// <summary>
    /// Maps a <see cref="TpmAlgIdConstants"/> hash algorithm identifier to the digest seam's <see cref="Tag"/>.
    /// Fails closed with <see cref="NotSupportedException"/> for an algorithm the TPM signing function does
    /// not support, rather than defaulting to SHA-256.
    /// </summary>
    /// <param name="hash">The TPM hash algorithm identifier.</param>
    /// <returns>The digest <see cref="Tag"/> for <paramref name="hash"/>.</returns>
    private static Tag BuildDigestTag(TpmAlgIdConstants hash) => hash switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA256 => CryptoTags.Sha256Digest,
        TpmAlgIdConstants.TPM_ALG_SHA384 => CryptoTags.Sha384Digest,
        TpmAlgIdConstants.TPM_ALG_SHA512 => CryptoTags.Sha512Digest,
        _ => throw new NotSupportedException($"Hash algorithm '{hash}' is not supported by the TPM signing function.")
    };

    /// <summary>
    /// Maps a <see cref="TpmAlgIdConstants"/> hash algorithm identifier to its digest output size in bytes.
    /// Fails closed with <see cref="NotSupportedException"/> for an algorithm the TPM signing function does
    /// not support, rather than defaulting to SHA-256.
    /// </summary>
    /// <param name="hash">The TPM hash algorithm identifier.</param>
    /// <returns>The digest output size in bytes for <paramref name="hash"/>.</returns>
    private static int GetDigestSize(TpmAlgIdConstants hash) => hash switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Hash algorithm '{hash}' is not supported by the TPM signing function.")
    };
}
