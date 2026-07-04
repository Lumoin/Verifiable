using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// An established ICAO Doc 9303 Secure Messaging session: it protects outgoing command APDUs and
/// unprotects incoming response APDUs under a pair of session keys and a send-sequence counter.
/// </summary>
/// <remarks>
/// <para>
/// After access control (BAC or PACE) derives the session keys KSenc / KSmac and the initial
/// send-sequence counter (SSC), every subsequent APDU is wrapped: the command header is masked and
/// padded, the command data is encrypted into DO'87', the expected length becomes DO'97', and a MAC
/// over the SSC-prefixed, padded message becomes DO'8E' (Doc 9303 Part 11, Section 9.8). The response
/// is the mirror: DO'87' / DO'99' / DO'8E', MAC-verified before anything is decrypted.
/// </para>
/// <para>
/// The cipher-specific details — block size, MAC, and how the IV is formed — come from a
/// <see cref="SecureMessagingProfile"/>, so one engine serves both the 3DES profile (BAC) and the
/// AES profile (PACE). The cryptographic work routes through the registered
/// <see cref="SymmetricEncryptDelegate"/>, <see cref="SymmetricDecryptDelegate"/>,
/// <see cref="ComputeBlockCipherMacDelegate"/>, and <see cref="VerifyBlockCipherMacDelegate"/>; the
/// session owns no cryptography of its own. Every working buffer is rented from
/// <see cref="BaseMemoryPool"/> — buffers holding plaintext, the derived IV, or the SSC-prefixed MAC
/// input are <see cref="AllocationKind.Pinned"/> so the zeroize-on-dispose actually wipes the secret,
/// while public wire bytes are <see cref="AllocationKind.Managed"/>. The SSC increments once per
/// protected command and once per unprotected response, exactly as the protocol requires.
/// </para>
/// </remarks>
public sealed class SecureMessagingSession: IDisposable
{
    /// <summary>The bit ISO 7816-4 sets in the class byte to mark a command as secure-messaged with a protected header.</summary>
    private const byte SecureMessagingClassBits = 0x0C;

    /// <summary>BER-TLV tag for the cryptogram data object (DO'87').</summary>
    private const byte CryptogramTag = 0x87;

    /// <summary>BER-TLV tag for the expected-length data object (DO'97').</summary>
    private const byte ExpectedLengthTag = 0x97;

    /// <summary>BER-TLV tag for the processing-status data object (DO'99').</summary>
    private const byte StatusTag = 0x99;

    /// <summary>BER-TLV tag for the cryptographic-checksum data object (DO'8E').</summary>
    private const byte MacTag = 0x8E;

    /// <summary>The leading byte of a DO'87' value: the padding-content indicator for ISO 9797-1 method 2.</summary>
    private const byte PaddingContentIndicator = 0x01;

    /// <summary>The ISO 9797-1 method 2 leading padding byte.</summary>
    private const byte PaddingMarker = 0x80;

    /// <summary>The largest command data field a short-length APDU can carry; beyond it the command uses extended length (ISO/IEC 7816-4 §5.1).</summary>
    private const int MaxShortCommandDataLength = 255;

    private SecureMessagingProfile Profile { get; }
    private SymmetricKeyMemory EncryptionKey { get; }
    private SymmetricKeyMemory MacKey { get; }
    private IMemoryOwner<byte> SendSequenceCounter { get; }
    private SymmetricEncryptDelegate Encrypt { get; }
    private SymmetricDecryptDelegate Decrypt { get; }
    private ComputeBlockCipherMacDelegate ComputeMac { get; }
    private VerifyBlockCipherMacDelegate VerifyMac { get; }
    private bool disposed;


    /// <summary>
    /// Initialises a Secure Messaging session from established session keys, the initial SSC, and a profile.
    /// </summary>
    /// <param name="encryptionKey">The KSenc session encryption key. Ownership transfers to this session.</param>
    /// <param name="macKey">The KSmac session MAC key. Ownership transfers to this session.</param>
    /// <param name="initialSendSequenceCounter">The initial SSC (the profile's block size in bytes) established by the access protocol.</param>
    /// <param name="profile">The cipher profile: <see cref="SecureMessagingProfile.TripleDes"/> for BAC or <see cref="SecureMessagingProfile.Aes128"/> for PACE.</param>
    /// <param name="pool">The sensitive-memory pool the session holds the SSC in.</param>
    /// <exception cref="ArgumentException">Thrown when the SSC is not the cipher block size.</exception>
    /// <exception cref="InvalidOperationException">Thrown when a required symmetric delegate has not been registered.</exception>
    public SecureMessagingSession(
        SymmetricKeyMemory encryptionKey,
        SymmetricKeyMemory macKey,
        ReadOnlySpan<byte> initialSendSequenceCounter,
        SecureMessagingProfile profile,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ArgumentNullException.ThrowIfNull(macKey);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(pool);

        if(initialSendSequenceCounter.Length != profile.BlockSize)
        {
            throw new ArgumentException(
                $"The initial SSC must be {profile.BlockSize} bytes but was {initialSendSequenceCounter.Length}.",
                nameof(initialSendSequenceCounter));
        }

        Profile = profile;
        EncryptionKey = encryptionKey;
        MacKey = macKey;

        //The SSC is mutable session state derived from the access nonces; it lives in pinned memory.
        SendSequenceCounter = pool.Rent(profile.BlockSize, AllocationKind.Pinned);
        initialSendSequenceCounter.CopyTo(SendSequenceCounter.Memory.Span);

        Encrypt = CryptographicKeyFactory.GetFunction<SymmetricEncryptDelegate>(typeof(SymmetricEncryptDelegate))
            ?? throw new InvalidOperationException("No SymmetricEncryptDelegate has been registered.");
        Decrypt = CryptographicKeyFactory.GetFunction<SymmetricDecryptDelegate>(typeof(SymmetricDecryptDelegate))
            ?? throw new InvalidOperationException("No SymmetricDecryptDelegate has been registered.");
        ComputeMac = CryptographicKeyFactory.GetFunction<ComputeBlockCipherMacDelegate>(typeof(ComputeBlockCipherMacDelegate))
            ?? throw new InvalidOperationException("No ComputeBlockCipherMacDelegate has been registered.");
        VerifyMac = CryptographicKeyFactory.GetFunction<VerifyBlockCipherMacDelegate>(typeof(VerifyBlockCipherMacDelegate))
            ?? throw new InvalidOperationException("No VerifyBlockCipherMacDelegate has been registered.");
    }


    /// <summary>
    /// Protects a command APDU: masks and pads the header, encrypts the command data into DO'87',
    /// encodes the expected length into DO'97', and appends the MAC as DO'8E'.
    /// </summary>
    /// <param name="cla">The unprotected class byte (the Secure Messaging bits are set here).</param>
    /// <param name="ins">The instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="commandData">The unprotected command data field; empty for commands that send none.</param>
    /// <param name="expectedResponseLength">The expected response length (Le, 0-256), or <see langword="null"/> when no response data is expected.</param>
    /// <param name="pool">The sensitive-memory pool for the working buffers and the protected APDU.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The protected command APDU. The caller disposes it.</returns>
    public async ValueTask<ProtectedCommandApdu> ProtectCommandAsync(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        ReadOnlyMemory<byte> commandData,
        int? expectedResponseLength,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ThrowIfDisposed();

        byte protectedCla = (byte)(cla | SecureMessagingClassBits);
        int blockSize = Profile.BlockSize;

        //Increment the SSC first: the AES profile derives this command's IV from it (the 3DES profile
        //uses a zero IV, so the order has no effect there).
        IncrementSendSequenceCounter();

        //DO'87' (public): the encrypted, padded command data, if any.
        IMemoryOwner<byte>? cryptogramObject = null;
        int cryptogramObjectLength = 0;
        try
        {
            if(!commandData.IsEmpty)
            {
                (cryptogramObject, cryptogramObjectLength) =
                    await BuildCryptogramObjectAsync(commandData, blockSize, pool, cancellationToken).ConfigureAwait(false);
            }

            int expectedLengthObjectLength = expectedResponseLength.HasValue ? 3 : 0;
            int paddedHeaderLength = Iso9797Padding.PaddedLength(ApduConstants.CommandHeaderSize, blockSize);

            //M = padded masked header || DO'87' || DO'97' (public).
            int mLength = paddedHeaderLength + cryptogramObjectLength + expectedLengthObjectLength;
            using IMemoryOwner<byte> message = pool.Rent(mLength);
            Span<byte> m = message.Memory.Span;
            Iso9797Padding.Pad([protectedCla, ins, p1, p2], blockSize, m[..paddedHeaderLength]);
            int offset = paddedHeaderLength;
            if(cryptogramObject is not null)
            {
                cryptogramObject.Memory.Span[..cryptogramObjectLength].CopyTo(m[offset..]);
                offset += cryptogramObjectLength;
            }

            if(expectedLengthObjectLength > 0)
            {
                WriteExpectedLengthObject(expectedResponseLength!.Value, m.Slice(offset, expectedLengthObjectLength));
            }

            //The MAC is over SSC || M, method-2 padded — a secret because it carries the SSC.
            using IMemoryOwner<byte> macInput = pool.Rent(
                Iso9797Padding.PaddedLength(blockSize + mLength, blockSize), AllocationKind.Pinned);
            WriteSequencePrefixedPaddedMac(SendSequenceCounter.Memory.Span, m, blockSize, macInput.Memory.Span);

            return await AssembleProtectedApduAsync(
                protectedCla, ins, p1, p2, message.Memory[paddedHeaderLength..], macInput.Memory, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            cryptogramObject?.Dispose();
        }
    }


    /// <summary>
    /// Unprotects a response APDU: verifies the DO'8E' MAC over the received data objects, then
    /// decrypts DO'87' (if present) and returns the data with the DO'99' status word.
    /// </summary>
    /// <param name="responseApdu">The full response APDU: the secure-messaging data objects followed by the transport status word.</param>
    /// <param name="pool">The sensitive-memory pool for the decrypted data.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The authenticated, decrypted <see cref="SecureMessagingResponse"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the response MAC does not verify — the response is tampered or the session has desynchronized.</exception>
    public async ValueTask<SecureMessagingResponse> UnprotectResponseAsync(
        ReadOnlyMemory<byte> responseApdu,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ThrowIfDisposed();

        ParsedResponse parsed = ParseResponse(responseApdu.Span);
        int blockSize = Profile.BlockSize;

        //K = SSC || DO'87' (if present) || DO'99', method-2 padded. Verify before decrypting anything.
        IncrementSendSequenceCounter();

        int macMessageLength = parsed.EncryptedObjectLength + parsed.StatusObjectLength;
        using(IMemoryOwner<byte> macInput = pool.Rent(
            Iso9797Padding.PaddedLength(blockSize + macMessageLength, blockSize), AllocationKind.Pinned))
        {
            WriteResponseMacInput(responseApdu.Span, parsed, blockSize, macInput.Memory.Span);

            (bool isValid, _) = await VerifyMac(
                macInput.Memory, MacKey.AsReadOnlyMemory(), responseApdu.Slice(parsed.MacStart, parsed.MacLength),
                Profile.MacTag, pool, null, cancellationToken).ConfigureAwait(false);
            if(!isValid)
            {
                throw new InvalidOperationException(
                    "Secure Messaging response MAC verification failed: the response is tampered or the session has desynchronized.");
            }
        }

        DecryptedContent? data = null;
        if(parsed.CryptogramLength > 0)
        {
            using IMemoryOwner<byte> iv = await ComputeInitializationVectorAsync(pool, cancellationToken).ConfigureAwait(false);
            (DecryptedContent padded, _) = await Decrypt(
                responseApdu.Slice(parsed.CryptogramStart, parsed.CryptogramLength), EncryptionKey.AsReadOnlyMemory(),
                iv.Memory, Profile.DecryptedContentTag, pool, null, cancellationToken).ConfigureAwait(false);
            try
            {
                data = RightSizeUnpadded(padded.AsReadOnlySpan(), pool);
            }
            finally
            {
                padded.Dispose();
            }
        }

        return new SecureMessagingResponse(data, parsed.StatusWord);
    }


    /// <summary>
    /// Encrypts the padded command data and wraps it as DO'87'. The plaintext and the IV are secrets
    /// held in pinned memory; the returned DO'87' is public wire bytes.
    /// </summary>
    private async ValueTask<(IMemoryOwner<byte> Object, int Length)> BuildCryptogramObjectAsync(
        ReadOnlyMemory<byte> commandData, int blockSize, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> paddedData = pool.Rent(
            Iso9797Padding.PaddedLength(commandData.Length, blockSize), AllocationKind.Pinned);
        Iso9797Padding.Pad(commandData.Span, blockSize, paddedData.Memory.Span);

        using IMemoryOwner<byte> iv = await ComputeInitializationVectorAsync(pool, cancellationToken).ConfigureAwait(false);
        (Ciphertext cryptogram, _) = await Encrypt(
            paddedData.Memory, EncryptionKey.AsReadOnlyMemory(), iv.Memory,
            Profile.CipherTag, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            int length = CryptogramObjectLength(cryptogram.AsReadOnlySpan().Length);
            IMemoryOwner<byte> dataObject = pool.Rent(length);
            WriteCryptogramObject(cryptogram.AsReadOnlySpan(), dataObject.Memory.Span);

            return (dataObject, length);
        }
        finally
        {
            cryptogram.Dispose();
        }
    }


    /// <summary>
    /// Assembles the protected command APDU into a pooled output buffer: masked header, Lc,
    /// DO'87' || DO'97' || DO'8E', and Le. The MAC over <paramref name="macInput"/> becomes DO'8E'.
    /// </summary>
    private async ValueTask<ProtectedCommandApdu> AssembleProtectedApduAsync(
        byte protectedCla, byte ins, byte p1, byte p2,
        ReadOnlyMemory<byte> cryptogramAndLengthObjects,
        ReadOnlyMemory<byte> macInput,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (MacValue mac, _) = await ComputeMac(
            macInput, MacKey.AsReadOnlyMemory(), Profile.MacLength, Profile.MacTag, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            int macObjectLength = 2 + mac.AsReadOnlySpan().Length;
            int protectedDataLength = cryptogramAndLengthObjects.Length + macObjectLength;

            //Case 4 framing (ISO/IEC 7816-4 §5.1): short uses a one-byte Lc and Le, extended a 0x00 marker then
            //a two-byte Lc and a two-byte Le. The protected data exceeds 255 bytes when a large command — such
            //as an RSA card-verifiable certificate presented in Terminal Authentication — is sent under Secure
            //Messaging, so the wrapper switches to extended length. Le 0x00 / 0x0000 both request the maximum.
            bool extended = protectedDataLength > MaxShortCommandDataLength;
            int lengthFieldsLength = extended ? 3 + 2 : 1 + 1;
            int total = ApduConstants.CommandHeaderSize + lengthFieldsLength + protectedDataLength;
            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new ApduWriter(owner.Memory.Span);
                writer.WriteHeader(protectedCla, ins, p1, p2);
                if(extended)
                {
                    writer.WriteByte(0x00);
                    writer.WriteByte((byte)(protectedDataLength >> 8));
                    writer.WriteByte((byte)protectedDataLength);
                }
                else
                {
                    writer.WriteByte((byte)protectedDataLength);
                }

                writer.WriteBytes(cryptogramAndLengthObjects.Span);
                writer.WriteByte(MacTag);
                writer.WriteByte((byte)mac.AsReadOnlySpan().Length);
                writer.WriteBytes(mac.AsReadOnlySpan());

                writer.WriteByte(0x00);
                if(extended)
                {
                    writer.WriteByte(0x00);
                }

                return new ProtectedCommandApdu(owner);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            mac.Dispose();
        }
    }


    /// <summary>
    /// Computes the per-message initialization vector: a fresh <c>E(KSenc, SSC)</c> for the AES profile
    /// (derived material, pinned), or the fixed zero IV for the 3DES profile.
    /// </summary>
    private async ValueTask<IMemoryOwner<byte>> ComputeInitializationVectorAsync(BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        if(!Profile.EncryptsSequenceCounterForIv)
        {
            //A rented buffer is zeroed, which is exactly the 3DES zero IV.
            return pool.Rent(Profile.BlockSize);
        }

        using IMemoryOwner<byte> zeroIv = pool.Rent(Profile.BlockSize);
        (Ciphertext derived, _) = await Encrypt(
            SendSequenceCounter.Memory, EncryptionKey.AsReadOnlyMemory(), zeroIv.Memory,
            Profile.CipherTag, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            IMemoryOwner<byte> iv = pool.Rent(derived.AsReadOnlySpan().Length, AllocationKind.Pinned);
            derived.AsReadOnlySpan().CopyTo(iv.Memory.Span);

            return iv;
        }
        finally
        {
            derived.Dispose();
        }
    }


    /// <summary>
    /// The encoded length of DO'87' (tag, length, padding-content indicator, cryptogram).
    /// </summary>
    private static int CryptogramObjectLength(int cryptogramLength)
    {
        int contentLength = 1 + cryptogramLength;

        return 1 + BerLengthFieldSize(contentLength) + contentLength;
    }


    /// <summary>
    /// Writes DO'87' = tag || length || padding-content-indicator || cryptogram into <paramref name="destination"/>.
    /// </summary>
    private static void WriteCryptogramObject(ReadOnlySpan<byte> cryptogram, Span<byte> destination)
    {
        int contentLength = 1 + cryptogram.Length;
        int lengthFieldSize = BerLengthFieldSize(contentLength);

        destination[0] = CryptogramTag;
        WriteBerLength(contentLength, destination[1..]);
        destination[1 + lengthFieldSize] = PaddingContentIndicator;
        cryptogram.CopyTo(destination[(1 + lengthFieldSize + 1)..]);
    }


    /// <summary>
    /// Writes DO'97' = tag || 0x01 || Le into <paramref name="destination"/>.
    /// </summary>
    private static void WriteExpectedLengthObject(int expectedResponseLength, Span<byte> destination)
    {
        destination[0] = ExpectedLengthTag;
        destination[1] = 0x01;
        destination[2] = (byte)expectedResponseLength;
    }


    /// <summary>
    /// Writes SSC || <paramref name="message"/> followed by ISO 9797-1 method 2 padding into
    /// <paramref name="destination"/> (which is rented zeroed, so only the marker is set).
    /// </summary>
    private static void WriteSequencePrefixedPaddedMac(
        ReadOnlySpan<byte> sendSequenceCounter, ReadOnlySpan<byte> message, int blockSize, Span<byte> destination)
    {
        sendSequenceCounter.CopyTo(destination);
        message.CopyTo(destination[blockSize..]);
        destination[blockSize + message.Length] = PaddingMarker;
    }


    /// <summary>
    /// Writes the response MAC input — SSC || DO'87' (if present) || DO'99' — followed by method 2
    /// padding, taking the data objects as slices of the response rather than copies.
    /// </summary>
    private static void WriteResponseMacInput(
        ReadOnlySpan<byte> responseApdu, ParsedResponse parsed, int blockSize, Span<byte> destination)
    {
        SpanCopySequenceCounter(parsed.SequenceCounter.Span, destination);
        int offset = blockSize;
        if(parsed.EncryptedObjectLength > 0)
        {
            responseApdu.Slice(parsed.EncryptedObjectStart, parsed.EncryptedObjectLength).CopyTo(destination[offset..]);
            offset += parsed.EncryptedObjectLength;
        }

        responseApdu.Slice(parsed.StatusObjectStart, parsed.StatusObjectLength).CopyTo(destination[offset..]);
        offset += parsed.StatusObjectLength;
        destination[offset] = PaddingMarker;
    }


    /// <summary>
    /// Copies the current send-sequence counter into the start of <paramref name="destination"/>.
    /// </summary>
    private static void SpanCopySequenceCounter(ReadOnlySpan<byte> sequenceCounter, Span<byte> destination) =>
        sequenceCounter.CopyTo(destination);


    /// <summary>
    /// Parses the secure-messaging data objects of a response APDU into byte ranges over the response.
    /// Synchronous so the <see cref="ApduReader"/> ref struct never crosses an <see langword="await"/>.
    /// </summary>
    private ParsedResponse ParseResponse(ReadOnlySpan<byte> responseApdu)
    {
        if(responseApdu.Length < ApduConstants.StatusWordSize)
        {
            throw new ArgumentException("The response is shorter than a status word.", nameof(responseApdu));
        }

        int encryptedObjectStart = -1, encryptedObjectLength = 0;
        int cryptogramStart = -1, cryptogramLength = 0;
        int statusObjectStart = -1, statusObjectLength = 0;
        int macStart = -1, macLength = 0;

        var reader = new ApduReader(responseApdu);

        //The data objects precede the two-byte transport status word.
        while(reader.Remaining > ApduConstants.StatusWordSize)
        {
            int start = reader.Consumed;
            byte tag = reader.ReadByte();
            int length = reader.ReadTlvLength();
            int valueStart = reader.Consumed;
            reader.Skip(length);

            switch(tag)
            {
                case(CryptogramTag):
                {
                    encryptedObjectStart = start;
                    encryptedObjectLength = reader.Consumed - start;
                    //The DO'87' value is the padding-content indicator followed by the cryptogram.
                    cryptogramStart = valueStart + 1;
                    cryptogramLength = length - 1;

                    break;
                }
                case(StatusTag):
                {
                    statusObjectStart = start;
                    statusObjectLength = reader.Consumed - start;

                    break;
                }
                case(MacTag):
                {
                    //Pin the MAC length to the profile. Taking it from the wire lets an attacker present a short
                    //or empty DO'8E': the verifier computes the real MAC truncated to that length and compares
                    //equal-length spans, so an 8E 00 (empty) MAC compares equal to an empty computed MAC and the
                    //channel authentication is bypassed with no key. Reject any length but the profile's.
                    if(length != Profile.MacLength)
                    {
                        throw new InvalidOperationException(
                            $"The Secure Messaging response MAC (DO'8E') is {length} bytes; the profile requires exactly {Profile.MacLength}.");
                    }

                    macStart = valueStart;
                    macLength = length;

                    break;
                }
                case(ExpectedLengthTag):
                {
                    //DO'97' is echoed in some responses; it is not part of the response MAC.
                    break;
                }
                default:
                {
                    throw new InvalidOperationException(
                        $"Unexpected Secure Messaging response data object tag 0x{tag:X2}.");
                }
            }
        }

        if(statusObjectStart < 0 || macStart < 0)
        {
            throw new InvalidOperationException("The Secure Messaging response is missing DO'99' or DO'8E'.");
        }

        //DO'99' value is the two status bytes; it sits at the end of the encoded object.
        StatusWord statusWord = StatusWord.FromBytes(
            responseApdu[statusObjectStart + statusObjectLength - ApduConstants.StatusWordSize],
            responseApdu[statusObjectStart + statusObjectLength - 1]);

        return new ParsedResponse(
            SendSequenceCounter.Memory,
            encryptedObjectStart, encryptedObjectLength,
            cryptogramStart, cryptogramLength,
            statusObjectStart, statusObjectLength,
            macStart, macLength,
            statusWord);
    }


    /// <summary>
    /// Copies the unpadded prefix of <paramref name="padded"/> — decrypted response content, a secret —
    /// into a pinned, right-sized <see cref="DecryptedContent"/> carrier.
    /// </summary>
    private DecryptedContent RightSizeUnpadded(ReadOnlySpan<byte> padded, BaseMemoryPool pool)
    {
        int length = Iso9797Padding.UnpaddedLength(padded);
        IMemoryOwner<byte> owner = pool.Rent(length, AllocationKind.Pinned);
        padded[..length].CopyTo(owner.Memory.Span);

        return new DecryptedContent(owner, Profile.DecryptedContentTag);
    }


    /// <summary>
    /// Increments the send-sequence counter as a big-endian integer (Doc 9303 §9.8.6.3).
    /// </summary>
    private void IncrementSendSequenceCounter()
    {
        Span<byte> counter = SendSequenceCounter.Memory.Span;
        for(int i = counter.Length - 1; i >= 0; i--)
        {
            if(++counter[i] != 0)
            {
                break;
            }
        }
    }


    /// <summary>
    /// The number of bytes a BER-TLV definite length field occupies for <paramref name="length"/>.
    /// </summary>
    private static int BerLengthFieldSize(int length) =>
        length <= 0x7F ? 1 : length <= 0xFF ? 2 : 3;


    /// <summary>
    /// Writes a BER-TLV definite length field for <paramref name="length"/> into <paramref name="destination"/>.
    /// </summary>
    private static void WriteBerLength(int length, Span<byte> destination)
    {
        if(length <= 0x7F)
        {
            destination[0] = (byte)length;
        }
        else if(length <= 0xFF)
        {
            destination[0] = 0x81;
            destination[1] = (byte)length;
        }
        else
        {
            destination[0] = 0x82;
            destination[1] = (byte)(length >> 8);
            destination[2] = (byte)length;
        }
    }


    /// <summary>
    /// Throws if this session has been disposed.
    /// </summary>
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            EncryptionKey.Dispose();
            MacKey.Dispose();
            SendSequenceCounter.Dispose();
            disposed = true;
        }
    }


    /// <summary>
    /// The secure-messaging data objects of a response APDU, expressed as ranges over the response
    /// buffer so the async unprotect path can slice them without copying.
    /// </summary>
    private readonly struct ParsedResponse(
        ReadOnlyMemory<byte> sequenceCounter,
        int encryptedObjectStart, int encryptedObjectLength,
        int cryptogramStart, int cryptogramLength,
        int statusObjectStart, int statusObjectLength,
        int macStart, int macLength,
        StatusWord statusWord)
    {
        /// <summary>The send-sequence counter to prefix the response MAC input with (a view into the session's SSC).</summary>
        public ReadOnlyMemory<byte> SequenceCounter { get; } = sequenceCounter;

        /// <summary>The start of the encoded DO'87' within the response, or <c>-1</c> when absent.</summary>
        public int EncryptedObjectStart { get; } = encryptedObjectStart;

        /// <summary>The length of the encoded DO'87', or <c>0</c> when absent.</summary>
        public int EncryptedObjectLength { get; } = encryptedObjectLength;

        /// <summary>The start of the cryptogram (past the DO'87' padding-content indicator), or <c>-1</c>.</summary>
        public int CryptogramStart { get; } = cryptogramStart;

        /// <summary>The length of the cryptogram, or <c>0</c> when absent.</summary>
        public int CryptogramLength { get; } = cryptogramLength;

        /// <summary>The start of the encoded DO'99' within the response.</summary>
        public int StatusObjectStart { get; } = statusObjectStart;

        /// <summary>The length of the encoded DO'99'.</summary>
        public int StatusObjectLength { get; } = statusObjectLength;

        /// <summary>The start of the DO'8E' MAC value within the response.</summary>
        public int MacStart { get; } = macStart;

        /// <summary>The length of the DO'8E' MAC value.</summary>
        public int MacLength { get; } = macLength;

        /// <summary>The status word decoded from DO'99'.</summary>
        public StatusWord StatusWord { get; } = statusWord;
    }
}
