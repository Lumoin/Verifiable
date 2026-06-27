using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// The card side of an ICAO Doc 9303 Secure Messaging session: it unprotects incoming command APDUs and
/// protects outgoing response APDUs, the mirror of <see cref="SecureMessagingSession"/> (which is the
/// terminal side). The two interoperate — a command protected by a terminal session unprotects here, and
/// a response protected here unprotects in the terminal session.
/// </summary>
/// <remarks>
/// <para>
/// This is the counterparty a software eMRTD needs to serve a terminal over an established session: it
/// keeps the send-sequence counter (SSC) in step (incremented once per unprotected command and once per
/// protected response, exactly as the terminal does), verifies each command MAC before decrypting, and
/// frames each response as DO'87' / DO'99' / DO'8E'. The cipher specifics come from a
/// <see cref="SecureMessagingProfile"/> and the cryptography routes through the same registered
/// symmetric delegates as the terminal session; this type owns no cryptography of its own.
/// </para>
/// </remarks>
public sealed class SecureMessagingCardSession: IDisposable
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

    /// <summary>The encoded length of DO'99' (tag, length, SW1, SW2).</summary>
    private const int StatusObjectLength = 4;

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
    /// Initialises the card side of a Secure Messaging session from the established session keys, the
    /// initial SSC, and a profile — the same inputs as the terminal-side <see cref="SecureMessagingSession"/>.
    /// </summary>
    /// <param name="encryptionKey">The KSenc session encryption key. Ownership transfers to this session.</param>
    /// <param name="macKey">The KSmac session MAC key. Ownership transfers to this session.</param>
    /// <param name="initialSendSequenceCounter">The initial SSC (the profile's block size in bytes).</param>
    /// <param name="profile">The cipher profile.</param>
    /// <param name="pool">The sensitive-memory pool the session holds the SSC in.</param>
    /// <exception cref="ArgumentException">Thrown when the SSC is not the cipher block size.</exception>
    /// <exception cref="InvalidOperationException">Thrown when a required symmetric delegate has not been registered.</exception>
    public SecureMessagingCardSession(
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
    /// Unprotects a command APDU: verifies the DO'8E' MAC over the masked header and data objects, then
    /// decrypts DO'87' (if present) to recover the command data and reads DO'97' for the expected length.
    /// </summary>
    /// <param name="protectedCommand">The protected command APDU as the terminal sent it.</param>
    /// <param name="pool">The sensitive-memory pool for the decrypted data.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The authenticated, decrypted <see cref="SecureMessagingCommand"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the command MAC does not verify — the command is tampered or the session has desynchronized.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the decrypted data transfers to the returned SecureMessagingCommand, which the caller disposes.")]
    public async ValueTask<SecureMessagingCommand> UnprotectCommandAsync(
        ReadOnlyMemory<byte> protectedCommand,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ThrowIfDisposed();

        ParsedCommand parsed = ParseCommand(protectedCommand.Span);
        int blockSize = Profile.BlockSize;

        //The terminal incremented the SSC before protecting; match it before verifying.
        IncrementSendSequenceCounter();

        //M = padded masked header || DO'87' || DO'97'; the MAC is over SSC || M, method-2 padded.
        int paddedHeaderLength = Iso9797Padding.PaddedLength(ApduConstants.CommandHeaderSize, blockSize);
        int messageLength = paddedHeaderLength + parsed.EncryptedObjectLength + parsed.ExpectedLengthObjectLength;
        using(IMemoryOwner<byte> macInput = pool.Rent(
            Iso9797Padding.PaddedLength(blockSize + messageLength, blockSize), AllocationKind.Pinned))
        {
            WriteCommandMacInput(protectedCommand.Span, parsed, blockSize, paddedHeaderLength, macInput.Memory.Span);

            (bool isValid, _) = await VerifyMac(
                macInput.Memory, MacKey.AsReadOnlyMemory(), protectedCommand.Slice(parsed.MacStart, parsed.MacLength),
                Profile.MacTag, pool, null, cancellationToken).ConfigureAwait(false);
            if(!isValid)
            {
                throw new InvalidOperationException(
                    "Secure Messaging command MAC verification failed: the command is tampered or the session has desynchronized.");
            }
        }

        DecryptedContent? data = null;
        if(parsed.CryptogramLength > 0)
        {
            using IMemoryOwner<byte> iv = await ComputeInitializationVectorAsync(pool, cancellationToken).ConfigureAwait(false);
            (DecryptedContent padded, _) = await Decrypt(
                protectedCommand.Slice(parsed.CryptogramStart, parsed.CryptogramLength), EncryptionKey.AsReadOnlyMemory(),
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

        ReadOnlySpan<byte> header = protectedCommand.Span;

        return new SecureMessagingCommand(
            (byte)(header[0] & ~SecureMessagingClassBits), header[1], header[2], header[3], data, parsed.ExpectedResponseLength);
    }


    /// <summary>
    /// Protects a response APDU: encrypts the response data into DO'87' (if any), encodes the status word
    /// in DO'99', and appends the MAC as DO'8E' followed by the transport-level <c>9000</c> status word.
    /// </summary>
    /// <param name="responseData">The unprotected response data; empty for a status-only response.</param>
    /// <param name="statusWord">The card's real status word, carried in DO'99'.</param>
    /// <param name="pool">The sensitive-memory pool for the working buffers and the protected APDU.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The protected response APDU. The caller disposes it.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the protected response buffer transfers to the returned ProtectedResponseApdu, which the caller disposes.")]
    public async ValueTask<ProtectedResponseApdu> ProtectResponseAsync(
        ReadOnlyMemory<byte> responseData,
        StatusWord statusWord,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ThrowIfDisposed();

        int blockSize = Profile.BlockSize;

        //Increment the SSC first: the AES profile derives this response's IV from it.
        IncrementSendSequenceCounter();

        IMemoryOwner<byte>? cryptogramObject = null;
        int cryptogramObjectLength = 0;
        try
        {
            if(!responseData.IsEmpty)
            {
                (cryptogramObject, cryptogramObjectLength) =
                    await BuildCryptogramObjectAsync(responseData, blockSize, pool, cancellationToken).ConfigureAwait(false);
            }

            ReadOnlyMemory<byte> cryptogramObjectMemory = cryptogramObject is null
                ? ReadOnlyMemory<byte>.Empty
                : cryptogramObject.Memory[..cryptogramObjectLength];

            //The MAC is over SSC || DO'87' (if present) || DO'99', method-2 padded — a secret (it carries the SSC).
            int dataObjectsLength = cryptogramObjectLength + StatusObjectLength;
            using IMemoryOwner<byte> macInput = pool.Rent(
                Iso9797Padding.PaddedLength(blockSize + dataObjectsLength, blockSize), AllocationKind.Pinned);
            WriteResponseMacInput(cryptogramObjectMemory.Span, statusWord, blockSize, macInput.Memory.Span);

            return await AssembleProtectedResponseAsync(
                cryptogramObjectMemory, statusWord, macInput.Memory, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            cryptogramObject?.Dispose();
        }
    }


    /// <summary>
    /// Encrypts the padded response data and wraps it as DO'87'. The plaintext and IV are secrets held in
    /// pinned memory; the returned DO'87' is public wire bytes.
    /// </summary>
    private async ValueTask<(IMemoryOwner<byte> Object, int Length)> BuildCryptogramObjectAsync(
        ReadOnlyMemory<byte> responseData, int blockSize, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> paddedData = pool.Rent(
            Iso9797Padding.PaddedLength(responseData.Length, blockSize), AllocationKind.Pinned);
        Iso9797Padding.Pad(responseData.Span, blockSize, paddedData.Memory.Span);

        using IMemoryOwner<byte> iv = await ComputeInitializationVectorAsync(pool, cancellationToken).ConfigureAwait(false);
        (Ciphertext cryptogram, _) = await Encrypt(
            paddedData.Memory, EncryptionKey.AsReadOnlyMemory(), iv.Memory, Profile.CipherTag, pool, null, cancellationToken).ConfigureAwait(false);
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
    /// Assembles the protected response APDU: DO'87' (if present), DO'99', the DO'8E' MAC over
    /// <paramref name="macInput"/>, and the transport status word <c>9000</c>.
    /// </summary>
    private async ValueTask<ProtectedResponseApdu> AssembleProtectedResponseAsync(
        ReadOnlyMemory<byte> cryptogramObject,
        StatusWord statusWord,
        ReadOnlyMemory<byte> macInput,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (MacValue mac, _) = await ComputeMac(
            macInput, MacKey.AsReadOnlyMemory(), Profile.MacLength, Profile.MacTag, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            int macObjectLength = 2 + mac.AsReadOnlySpan().Length;
            int total = cryptogramObject.Length + StatusObjectLength + macObjectLength + ApduConstants.StatusWordSize;
            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new ApduWriter(owner.Memory.Span);
                writer.WriteBytes(cryptogramObject.Span);
                writer.WriteByte(StatusTag);
                writer.WriteByte(0x02);
                writer.WriteByte(statusWord.Sw1);
                writer.WriteByte(statusWord.Sw2);
                writer.WriteByte(MacTag);
                writer.WriteByte((byte)mac.AsReadOnlySpan().Length);
                writer.WriteBytes(mac.AsReadOnlySpan());
                writer.WriteByte(0x90);
                writer.WriteByte(0x00);

                return new ProtectedResponseApdu(owner);
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
    /// Writes the command MAC input — SSC || padded masked header || DO'87' (if present) || DO'97' (if
    /// present) — followed by the method 2 padding marker, into the zeroed <paramref name="destination"/>.
    /// </summary>
    private void WriteCommandMacInput(
        ReadOnlySpan<byte> protectedCommand, ParsedCommand parsed, int blockSize, int paddedHeaderLength, Span<byte> destination)
    {
        destination.Clear();
        SendSequenceCounter.Memory.Span.CopyTo(destination);
        int offset = blockSize;

        Iso9797Padding.Pad(protectedCommand[..ApduConstants.CommandHeaderSize], blockSize, destination.Slice(offset, paddedHeaderLength));
        offset += paddedHeaderLength;

        if(parsed.EncryptedObjectLength > 0)
        {
            protectedCommand.Slice(parsed.EncryptedObjectStart, parsed.EncryptedObjectLength).CopyTo(destination[offset..]);
            offset += parsed.EncryptedObjectLength;
        }

        if(parsed.ExpectedLengthObjectLength > 0)
        {
            protectedCommand.Slice(parsed.ExpectedLengthObjectStart, parsed.ExpectedLengthObjectLength).CopyTo(destination[offset..]);
            offset += parsed.ExpectedLengthObjectLength;
        }

        destination[offset] = PaddingMarker;
    }


    /// <summary>
    /// Writes the response MAC input — SSC || DO'87' (if present) || DO'99' — followed by the method 2
    /// padding marker, into the zeroed <paramref name="destination"/>.
    /// </summary>
    private void WriteResponseMacInput(ReadOnlySpan<byte> cryptogramObject, StatusWord statusWord, int blockSize, Span<byte> destination)
    {
        destination.Clear();
        SendSequenceCounter.Memory.Span.CopyTo(destination);
        int offset = blockSize;

        if(cryptogramObject.Length > 0)
        {
            cryptogramObject.CopyTo(destination[offset..]);
            offset += cryptogramObject.Length;
        }

        WriteStatusObject(statusWord, destination.Slice(offset, StatusObjectLength));
        offset += StatusObjectLength;

        destination[offset] = PaddingMarker;
    }


    /// <summary>
    /// Writes DO'99' = tag || 0x02 || SW1 || SW2 into <paramref name="destination"/>.
    /// </summary>
    private static void WriteStatusObject(StatusWord statusWord, Span<byte> destination)
    {
        destination[0] = StatusTag;
        destination[1] = 0x02;
        destination[2] = statusWord.Sw1;
        destination[3] = statusWord.Sw2;
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
    /// Copies the unpadded prefix of <paramref name="padded"/> — decrypted command content, a secret —
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
    /// Parses the secure-messaging data objects of a protected command APDU into byte ranges over it.
    /// Synchronous so the <see cref="ApduReader"/> ref struct never crosses an <see langword="await"/>.
    /// </summary>
    private static ParsedCommand ParseCommand(ReadOnlySpan<byte> protectedCommand)
    {
        if(protectedCommand.Length < ApduConstants.CommandHeaderSize + 1)
        {
            throw new ArgumentException("The protected command is shorter than a header and length byte.", nameof(protectedCommand));
        }

        int encryptedObjectStart = -1, encryptedObjectLength = 0;
        int cryptogramStart = -1, cryptogramLength = 0;
        int expectedLengthObjectStart = -1, expectedLengthObjectLength = 0;
        int macStart = -1, macLength = 0;
        int? expectedResponseLength = null;

        var reader = new ApduReader(protectedCommand);
        reader.Skip(ApduConstants.CommandHeaderSize);

        //Lc is a single byte for a short command; an extended command (data over 255 bytes) encodes it as a
        //0x00 marker followed by a two-byte length (ISO/IEC 7816-4 §5.1). A protected command always carries
        //data (DO'8E' at minimum), so a leading 0x00 unambiguously marks the extended form.
        int dataLength = reader.ReadByte();
        if(dataLength == 0x00)
        {
            dataLength = (reader.ReadByte() << 8) | reader.ReadByte();
        }

        int dataEnd = reader.Consumed + dataLength;

        while(reader.Consumed < dataEnd)
        {
            int start = reader.Consumed;
            byte tag = reader.ReadByte();
            int length = reader.ReadTlvLength();
            int valueStart = reader.Consumed;
            reader.Skip(length);

            switch(tag)
            {
                case CryptogramTag:
                    encryptedObjectStart = start;
                    encryptedObjectLength = reader.Consumed - start;
                    //The DO'87' value is the padding-content indicator followed by the cryptogram.
                    cryptogramStart = valueStart + 1;
                    cryptogramLength = length - 1;
                    break;
                case ExpectedLengthTag:
                    expectedLengthObjectStart = start;
                    expectedLengthObjectLength = reader.Consumed - start;
                    expectedResponseLength = protectedCommand[valueStart];
                    break;
                case MacTag:
                    macStart = valueStart;
                    macLength = length;
                    break;
                default:
                    throw new InvalidOperationException($"Unexpected Secure Messaging command data object tag 0x{tag:X2}.");
            }
        }

        if(macStart < 0)
        {
            throw new InvalidOperationException("The Secure Messaging command is missing DO'8E'.");
        }

        return new ParsedCommand(
            encryptedObjectStart, encryptedObjectLength, cryptogramStart, cryptogramLength,
            expectedLengthObjectStart, expectedLengthObjectLength, expectedResponseLength, macStart, macLength);
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
    /// The secure-messaging data objects of a protected command APDU, as ranges over the command buffer.
    /// </summary>
    private readonly struct ParsedCommand(
        int encryptedObjectStart, int encryptedObjectLength,
        int cryptogramStart, int cryptogramLength,
        int expectedLengthObjectStart, int expectedLengthObjectLength,
        int? expectedResponseLength,
        int macStart, int macLength)
    {
        /// <summary>The start of the encoded DO'87' within the command, or <c>-1</c> when absent.</summary>
        public int EncryptedObjectStart { get; } = encryptedObjectStart;

        /// <summary>The length of the encoded DO'87', or <c>0</c> when absent.</summary>
        public int EncryptedObjectLength { get; } = encryptedObjectLength;

        /// <summary>The start of the cryptogram (past the DO'87' padding-content indicator), or <c>-1</c>.</summary>
        public int CryptogramStart { get; } = cryptogramStart;

        /// <summary>The length of the cryptogram, or <c>0</c> when absent.</summary>
        public int CryptogramLength { get; } = cryptogramLength;

        /// <summary>The start of the encoded DO'97' within the command, or <c>-1</c> when absent.</summary>
        public int ExpectedLengthObjectStart { get; } = expectedLengthObjectStart;

        /// <summary>The length of the encoded DO'97', or <c>0</c> when absent.</summary>
        public int ExpectedLengthObjectLength { get; } = expectedLengthObjectLength;

        /// <summary>The expected response length from DO'97', or <see langword="null"/> when absent.</summary>
        public int? ExpectedResponseLength { get; } = expectedResponseLength;

        /// <summary>The start of the DO'8E' MAC value within the command.</summary>
        public int MacStart { get; } = macStart;

        /// <summary>The length of the DO'8E' MAC value.</summary>
        public int MacLength { get; } = macLength;
    }
}
