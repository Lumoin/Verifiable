using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.BouncyCastle;

/// <summary>
/// Unauthenticated symmetric block-cipher (CBC) and block-cipher MAC functions backed by
/// BouncyCastle, for protocols that compose confidentiality and integrity from separate
/// primitives — notably ICAO Doc 9303 Secure Messaging.
/// </summary>
/// <remarks>
/// <para>
/// Register these at application startup when the BouncyCastle backend is preferred for
/// symmetric block-cipher operations:
/// </para>
/// <code>
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(SymmetricEncryptDelegate),
///     (SymmetricEncryptDelegate)BouncyCastleSymmetricFunctions.SymmetricEncryptAsync);
/// </code>
/// <para>
/// The block cipher / MAC construction is selected by the
/// <see cref="CryptoAlgorithm"/> carried in the operation <see cref="Tag"/>. This first
/// increment supports two-key Triple-DES (eMRTD Basic Access Control and 3DES Secure
/// Messaging): CBC mode for the cipher and the ISO/IEC 9797-1 MAC Algorithm 3 ("Retail
/// MAC") over DES for the MAC. AES (CBC + CMAC, for PACE) is added alongside the PACE work.
/// </para>
/// <para>
/// Each operation uses <see cref="CryptoProviderInstrumentation"/> to stamp the <see cref="Tag"/>
/// with provenance entries and set standard <see cref="CryptoTelemetry"/> attributes on the OTel
/// activity, exactly as the digest and HMAC backends do.
/// </para>
/// </remarks>
public static class BouncyCastleSymmetricFunctions
{
    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(BouncyCastleSymmetricFunctions).Assembly.GetName().Name
            ?? "Verifiable.BouncyCastle",
        typeof(BouncyCastleSymmetricFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    //BouncyCastle is an independently versioned NuGet package — its assembly version is the
    //most meaningful CBOM identifier.
    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "Org.BouncyCastle.Cryptography",
        typeof(DesEdeEngine).Assembly.GetName().Version?.ToString() ?? "Unknown");

    private static ProviderClass ProviderCls { get; } =
        new(nameof(BouncyCastleSymmetricFunctions));

    /// <summary>The DES/Triple-DES cipher block size in octets, shared by the CBC cipher and the Retail MAC.</summary>
    private const int DesBlockSize = 8;

    /// <summary>The AES cipher block size in octets, shared by the CBC cipher and CMAC.</summary>
    private const int AesBlockSize = 16;


    /// <summary>
    /// Encrypts block-aligned <paramref name="plaintext"/> with the block cipher selected by the
    /// <see cref="CryptoAlgorithm"/> in <paramref name="tag"/>, in CBC mode with no padding.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned Ciphertext takes ownership of the IMemoryOwner and is disposed by the caller.")]
    public static ValueTask<(Ciphertext Result, CryptoEvent? Event)> SymmetricEncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        ReadOnlyMemory<byte> keyBytes,
        ReadOnlyMemory<byte> iv,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();
        _ = context;

        CryptoAlgorithm algorithm = RequireAlgorithm(tag);

        ProviderOperation operation = new(nameof(SymmetricEncryptAsync));
        Tag stamped = CryptoProviderInstrumentation.StampTag(tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.SymmetricEncrypt);
        if(activity is not null)
        {
            SetCipherAttributes(activity, operation, algorithm, plaintext.Length);
        }

        IMemoryOwner<byte> owner = CbcTransform(plaintext.Span, keyBytes.Span, iv.Span, algorithm, forEncryption: true, pool);
        Ciphertext result = new(owner, stamped, activity);
        CryptoEvent evt = SymmetricCipherPerformedEvent.Create(
            algorithm, encrypting: true, plaintext.Length, owner.Memory.Length, CryptoLib.Name);

        return ValueTask.FromResult<(Ciphertext, CryptoEvent?)>((result, evt));
    }


    /// <summary>
    /// Decrypts block-aligned <paramref name="ciphertext"/> with the block cipher selected by the
    /// <see cref="CryptoAlgorithm"/> in <paramref name="tag"/>, in CBC mode with no padding. The
    /// returned plaintext is still padded; the caller strips the padding.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned DecryptedContent takes ownership of the IMemoryOwner and is disposed by the caller.")]
    public static ValueTask<(DecryptedContent Result, CryptoEvent? Event)> SymmetricDecryptAsync(
        ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> keyBytes,
        ReadOnlyMemory<byte> iv,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();
        _ = context;

        CryptoAlgorithm algorithm = RequireAlgorithm(tag);

        ProviderOperation operation = new(nameof(SymmetricDecryptAsync));
        Tag stamped = CryptoProviderInstrumentation.StampTag(tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.SymmetricDecrypt);
        if(activity is not null)
        {
            SetCipherAttributes(activity, operation, algorithm, ciphertext.Length);
        }

        IMemoryOwner<byte> owner = CbcTransform(ciphertext.Span, keyBytes.Span, iv.Span, algorithm, forEncryption: false, pool);
        DecryptedContent result = new(owner, stamped, activity);
        CryptoEvent evt = SymmetricCipherPerformedEvent.Create(
            algorithm, encrypting: false, ciphertext.Length, owner.Memory.Length, CryptoLib.Name);

        return ValueTask.FromResult<(DecryptedContent, CryptoEvent?)>((result, evt));
    }


    /// <summary>
    /// Computes a block-cipher MAC over block-aligned <paramref name="message"/> with the
    /// construction selected by the <see cref="CryptoAlgorithm"/> in <paramref name="tag"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned MacValue takes ownership of the IMemoryOwner and is disposed by the caller.")]
    public static ValueTask<(MacValue Result, CryptoEvent? Event)> ComputeBlockCipherMacAsync(
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(outputByteLength, 0);
        cancellationToken.ThrowIfCancellationRequested();
        _ = context;

        CryptoAlgorithm algorithm = RequireAlgorithm(tag);

        ProviderOperation operation = new(nameof(ComputeBlockCipherMacAsync));
        Tag stamped = CryptoProviderInstrumentation.StampTag(tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.BlockCipherMacCompute);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.BlockCipherMac.Algorithm, algorithm.ToString());
            activity.SetTag(CryptoTelemetry.BlockCipherMac.InputLength, message.Length);
            activity.SetTag(CryptoTelemetry.BlockCipherMac.OutputLength, outputByteLength);
        }

        IMemoryOwner<byte> owner = ComputeMacCore(message.Span, keyBytes.Span, outputByteLength, algorithm, pool);
        MacValue result = new(owner, stamped, activity);
        CryptoEvent evt = BlockCipherMacComputedEvent.Create(
            algorithm, message.Length, outputByteLength, CryptoLib.Name);

        return ValueTask.FromResult<(MacValue, CryptoEvent?)>((result, evt));
    }


    /// <summary>
    /// Verifies a block-cipher MAC over block-aligned <paramref name="message"/> against
    /// <paramref name="expectedMac"/> using constant-time comparison.
    /// </summary>
    public static ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyBlockCipherMacAsync(
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        ReadOnlyMemory<byte> expectedMac,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();
        _ = context;

        CryptoAlgorithm algorithm = RequireAlgorithm(tag);

        ProviderOperation operation = new(nameof(VerifyBlockCipherMacAsync));
        _ = CryptoProviderInstrumentation.StampTag(tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.BlockCipherMacVerify);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.BlockCipherMac.Algorithm, algorithm.ToString());
            activity.SetTag(CryptoTelemetry.BlockCipherMac.InputLength, message.Length);
        }

        bool isValid;
        using(IMemoryOwner<byte> owner = ComputeMacCore(message.Span, keyBytes.Span, expectedMac.Length, algorithm, pool))
        {
            isValid = CryptographicOperations.FixedTimeEquals(owner.Memory.Span, expectedMac.Span);
            owner.Memory.Span.Clear();
        }

        activity?.SetTag(CryptoTelemetry.BlockCipherMac.Valid, isValid);
        activity?.Stop();

        VerificationOutcome outcome = isValid ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
        CryptoEvent evt = BlockCipherMacVerifiedEvent.Create(algorithm, outcome, message.Length, CryptoLib.Name);

        return ValueTask.FromResult<(bool, CryptoEvent?)>((isValid, evt));
    }


    /// <summary>
    /// Reads the <see cref="CryptoAlgorithm"/> the operation tag must carry to select the cipher / MAC.
    /// </summary>
    private static CryptoAlgorithm RequireAlgorithm(Tag tag)
    {
        if(!tag.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new ArgumentException(
                "The tag must carry a CryptoAlgorithm to select the block cipher.", nameof(tag));
        }

        return algorithm;
    }


    /// <summary>
    /// Sets the provider and cipher attributes on a symmetric-cipher activity.
    /// </summary>
    private static void SetCipherAttributes(Activity activity, ProviderOperation operation, CryptoAlgorithm algorithm, int inputLength)
    {
        CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
        activity.SetTag(CryptoTelemetry.SymmetricCipher.Algorithm, algorithm.ToString());
        activity.SetTag(CryptoTelemetry.SymmetricCipher.InputLength, inputLength);
        activity.SetTag(CryptoTelemetry.SymmetricCipher.OutputLength, inputLength);
    }


    /// <summary>
    /// Runs the block-aligned, no-padding CBC transform into a freshly rented buffer, zeroing every
    /// transient copy of key and data on the way out.
    /// </summary>
    private static IMemoryOwner<byte> CbcTransform(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        CryptoAlgorithm algorithm,
        bool forEncryption,
        MemoryPool<byte> pool)
    {
        (IBlockCipher engine, int blockSize) = ResolveBlockCipher(algorithm);
        ValidateKeyLength(algorithm, key.Length);

        if(iv.Length != blockSize)
        {
            throw new ArgumentException(
                $"The IV must be exactly the cipher block size ({blockSize} bytes) but was {iv.Length}.", nameof(iv));
        }

        if(input.Length == 0 || input.Length % blockSize != 0)
        {
            throw new ArgumentException(
                $"The input must be a non-empty whole number of {blockSize}-byte blocks but was {input.Length} bytes.", nameof(input));
        }

        //The KeyParameter and ParametersWithIV span ctors copy the key and IV into BouncyCastle's own
        //buffers — no naked byte[] of key material for us to track and zero. BufferedBlockCipher's
        //ProcessBytes/DoFinal remain byte[]-only, so the plaintext/ciphertext data is still copied into
        //transient arrays that are zeroed in the finally block.
        BufferedBlockCipher cipher = new(new CbcBlockCipher(engine));
        cipher.Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] inputArray = input.ToArray();
        byte[] outputArray = new byte[cipher.GetOutputSize(inputArray.Length)];
        try
        {
            int written = cipher.ProcessBytes(inputArray, 0, inputArray.Length, outputArray, 0);
            written += cipher.DoFinal(outputArray, written);

            IMemoryOwner<byte> owner = pool.Rent(written);
            outputArray.AsSpan(0, written).CopyTo(owner.Memory.Span);
            return owner;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inputArray);
            CryptographicOperations.ZeroMemory(outputArray);
        }
    }


    /// <summary>
    /// Computes the block-cipher MAC into a freshly rented buffer, zeroing every transient copy.
    /// </summary>
    private static IMemoryOwner<byte> ComputeMacCore(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> key,
        int outputByteLength,
        CryptoAlgorithm algorithm,
        MemoryPool<byte> pool)
    {
        IMac mac = ResolveMac(algorithm, outputByteLength);
        ValidateKeyLength(algorithm, key.Length);

        //The KeyParameter span ctor copies the key into BouncyCastle's own buffer — no naked byte[]
        //of key material for us to track and zero.
        mac.Init(new KeyParameter(key));

        if(RequiresBlockAlignedMacInput(algorithm))
        {
            int blockSize = MacBlockSize(algorithm);
            if(message.Length == 0 || message.Length % blockSize != 0)
            {
                throw new ArgumentException(
                    $"The MAC message must be a non-empty whole number of {blockSize}-byte blocks but was {message.Length} bytes.", nameof(message));
            }
        }

        byte[] messageArray = message.ToArray();
        try
        {
            mac.BlockUpdate(messageArray, 0, messageArray.Length);

            byte[] macArray = new byte[mac.GetMacSize()];
            try
            {
                mac.DoFinal(macArray, 0);

                IMemoryOwner<byte> owner = pool.Rent(outputByteLength);
                macArray.AsSpan(0, outputByteLength).CopyTo(owner.Memory.Span);
                return owner;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(macArray);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageArray);
        }
    }


    /// <summary>
    /// Resolves the block cipher engine and its block size for <paramref name="algorithm"/>.
    /// </summary>
    private static (IBlockCipher Engine, int BlockSize) ResolveBlockCipher(CryptoAlgorithm algorithm)
    {
        if(algorithm == CryptoAlgorithm.TripleDes)
        {
            return (new DesEdeEngine(), DesBlockSize);
        }

        if(algorithm == CryptoAlgorithm.Aes128 || algorithm == CryptoAlgorithm.Aes256)
        {
            return (new AesEngine(), AesBlockSize);
        }

        throw new ArgumentException(
            $"Symmetric CBC is not implemented for algorithm '{algorithm}'.", nameof(algorithm));
    }


    /// <summary>
    /// Resolves the MAC construction for <paramref name="algorithm"/>, sized to
    /// <paramref name="outputByteLength"/> bytes with no internal padding (the caller pre-pads).
    /// </summary>
    [SuppressMessage("Performance", "CA1859:Use concrete types when possible for improved performance", Justification = "Returns IMac so additional MAC constructions (AES-CMAC for PACE) can be added without changing the signature.")]
    private static IMac ResolveMac(CryptoAlgorithm algorithm, int outputByteLength)
    {
        if(algorithm == CryptoAlgorithm.TripleDes)
        {
            //ISO/IEC 9797-1 MAC Algorithm 3 over a single DES engine, keyed by the 16-byte key:
            //single-DES CBC through every block but the last, then a final two-key 3DES transform.
            return new ISO9797Alg3Mac(new DesEngine(), outputByteLength * 8);
        }

        if(algorithm == CryptoAlgorithm.Aes128 || algorithm == CryptoAlgorithm.Aes256)
        {
            //AES-CMAC (RFC 4493); the requested output length truncates the 16-byte tag from the left.
            return new CMac(new AesEngine(), outputByteLength * 8);
        }

        throw new ArgumentException(
            $"Block-cipher MAC is not implemented for algorithm '{algorithm}'.", nameof(algorithm));
    }


    /// <summary>
    /// The block size the MAC message must be aligned to for <paramref name="algorithm"/>.
    /// </summary>
    private static int MacBlockSize(CryptoAlgorithm algorithm)
    {
        if(algorithm == CryptoAlgorithm.TripleDes)
        {
            return DesBlockSize;
        }

        if(algorithm == CryptoAlgorithm.Aes128 || algorithm == CryptoAlgorithm.Aes256)
        {
            return AesBlockSize;
        }

        throw new ArgumentException(
            $"Block-cipher MAC is not implemented for algorithm '{algorithm}'.", nameof(algorithm));
    }


    /// <summary>
    /// Whether the MAC construction for <paramref name="algorithm"/> requires block-aligned input.
    /// The ISO 9797-1 Retail MAC is invoked with no internal padding (the caller pre-pads), so it
    /// requires alignment; AES-CMAC pads internally per RFC 4493 and accepts any length.
    /// </summary>
    private static bool RequiresBlockAlignedMacInput(CryptoAlgorithm algorithm) =>
        algorithm == CryptoAlgorithm.TripleDes;


    /// <summary>
    /// Validates that <paramref name="keyLength"/> is a legal key size for <paramref name="algorithm"/>.
    /// </summary>
    private static void ValidateKeyLength(CryptoAlgorithm algorithm, int keyLength)
    {
        if(algorithm == CryptoAlgorithm.TripleDes)
        {
            if(keyLength is not (16 or 24))
            {
                throw new ArgumentException(
                    $"A Triple-DES key must be 16 or 24 bytes but was {keyLength}.", nameof(keyLength));
            }

            return;
        }

        if(algorithm == CryptoAlgorithm.Aes128)
        {
            if(keyLength != 16)
            {
                throw new ArgumentException($"An AES-128 key must be 16 bytes but was {keyLength}.", nameof(keyLength));
            }

            return;
        }

        if(algorithm == CryptoAlgorithm.Aes256)
        {
            if(keyLength != 32)
            {
                throw new ArgumentException($"An AES-256 key must be 32 bytes but was {keyLength}.", nameof(keyLength));
            }

            return;
        }

        throw new ArgumentException(
            $"Key validation is not implemented for algorithm '{algorithm}'.", nameof(algorithm));
    }
}