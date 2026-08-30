using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Seal;

/// <summary>
/// The persistable result of <see cref="TpmDeviceExtensions.SealEnvelopeAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, AeadEncryptDelegate, ReadOnlyMemory{byte}, bool, System.Threading.CancellationToken)"/>:
/// a content-encryption key sealed by the TPM (<see cref="SealedKey"/>) and the caller's data encrypted under
/// that key with an AEAD, bound to the sealed key through the additional authenticated data — the composition
/// that lets a secret of any width ride a sealed data object, which carries at most
/// <see cref="Tpm2bSensitiveData.MaxSize"/> (<c>MAX_SYM_DATA</c>, 128) octets (TPM 2.0 Library Part 2, clause
/// 11.1.13, Table 169; clause 11.1.14, Table 170).
/// </summary>
/// <remarks>
/// <para>
/// The persisted form is <see cref="SealedKey"/> (<see cref="TpmSealedBlob.WriteTo"/>), then the IV and the
/// authentication tag each <c>UINT16</c>-prefixed, then the ciphertext <c>UINT32</c>-prefixed;
/// <see cref="Parse"/> rebuilds an independent instance from those bytes alone and refuses trailing octets. The
/// additional authenticated data is the serialized sealed key, re-derived from <see cref="SealedKey"/> at unseal
/// rather than read back from the store, so a ciphertext opens only under exactly the sealed object it was bound
/// to and a re-encoded sealed key fails authentication instead of being trusted.
/// </para>
/// <para>
/// Every carrier is pooled and owned by this instance; dispose it once the envelope is persisted (its bytes
/// copied out via <see cref="WriteTo"/>) or consumed by
/// <see cref="TpmDeviceExtensions.UnsealEnvelopeAsync(uint, ReadOnlyMemory{byte}, TpmSealedEnvelope, ReadOnlyMemory{byte}, AeadDecryptDelegate, System.Threading.CancellationToken)"/> /
/// <see cref="TpmDeviceExtensions.UnsealEnvelopeUnderPolicyAsync(uint, ReadOnlyMemory{byte}, TpmSealedEnvelope, uint, AeadDecryptDelegate, System.Threading.CancellationToken)"/>.
/// Shaped like <see cref="TpmSealedBlob"/> rather than as a record: no value-equality contract is offered over
/// pooled, disposable buffer ownership.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmSealedEnvelope: IDisposable
{
    /// <summary>Whether the carriers this envelope owns have already been released.</summary>
    private bool isDisposed;

    /// <summary>Gets the TPM-sealed content-encryption key the ciphertext is bound to.</summary>
    public TpmSealedBlob SealedKey { get; }

    /// <summary>Gets the AEAD initialization vector.</summary>
    public Nonce Iv { get; }

    /// <summary>Gets the AEAD authentication tag.</summary>
    public AuthenticationTag Tag { get; }

    /// <summary>Gets the encrypted data.</summary>
    public Ciphertext Ciphertext { get; }

    /// <summary>Initializes an envelope, adopting ownership of every carrier.</summary>
    /// <param name="sealedKey">The sealed content key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="tag">The authentication tag.</param>
    /// <param name="ciphertext">The encrypted data.</param>
    private TpmSealedEnvelope(TpmSealedBlob sealedKey, Nonce iv, AuthenticationTag tag, Ciphertext ciphertext)
    {
        SealedKey = sealedKey;
        Iv = iv;
        Tag = tag;
        Ciphertext = ciphertext;
    }

    /// <summary>
    /// Gets the serialized size of this envelope, exactly as <see cref="WriteTo"/> writes it.
    /// </summary>
    /// <returns>The size, in octets, that <see cref="WriteTo"/> writes.</returns>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);

        return SealedKey.GetSerializedSize()
            + sizeof(ushort) + Iv.AsReadOnlySpan().Length
            + sizeof(ushort) + Tag.AsReadOnlySpan().Length
            + sizeof(uint) + Ciphertext.AsReadOnlySpan().Length;
    }

    /// <summary>
    /// Writes this envelope to a TPM writer — the sealed key, then the IV, the tag and the ciphertext, each
    /// length-prefixed — the disk/DB persistence format a caller round-trips through <see cref="Parse"/>.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);

        SealedKey.WriteTo(ref writer);
        writer.WriteTpm2b(Iv.AsReadOnlySpan());
        writer.WriteTpm2b(Tag.AsReadOnlySpan());

        ReadOnlySpan<byte> ciphertext = Ciphertext.AsReadOnlySpan();
        writer.WriteUInt32((uint)ciphertext.Length);
        writer.WriteBytes(ciphertext);
    }

    /// <summary>
    /// Parses an envelope previously written by <see cref="WriteTo"/> — the disk/DB round trip between a seal
    /// and a later unseal — reconstructing an instance with no ties to the TPM session that created it. The
    /// reader must end where the envelope ends: trailing octets are refused, so a stored envelope that grew is
    /// never partially trusted.
    /// </summary>
    /// <param name="reader">The reader positioned at a previously written envelope.</param>
    /// <param name="pool">The memory pool backing the parsed carriers.</param>
    /// <returns>The parsed envelope; the caller owns and disposes it.</returns>
    /// <exception cref="InvalidOperationException">A structure inside the envelope is malformed, or the envelope carries trailing octets.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A declared length exceeds the octets remaining.</exception>
    public static TpmSealedEnvelope Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmSealedBlob sealedKey = TpmSealedBlob.Parse(ref reader, pool);
        Nonce? iv = null;
        AuthenticationTag? tag = null;
        try
        {
            iv = new Nonce(ReadSized(ref reader, pool), CryptoTags.AesGcmIv);
            tag = new AuthenticationTag(ReadSized(ref reader, pool), CryptoTags.AesGcmAuthTag);
            int ciphertextLength = checked((int)reader.ReadUInt32());
            var ciphertext = new Ciphertext(Copy(reader.ReadBytes(ciphertextLength), pool), CryptoTags.AesGcmCiphertext);
            if(reader.Remaining != 0)
            {
                ciphertext.Dispose();

                throw new InvalidOperationException($"The sealed envelope carries {reader.Remaining} trailing octets.");
            }

            return new TpmSealedEnvelope(sealedKey, iv, tag, ciphertext);
        }
        catch
        {
            sealedKey.Dispose();
            iv?.Dispose();
            tag?.Dispose();

            throw;
        }
    }

    /// <summary>
    /// Builds an envelope from a freshly sealed content key and the AEAD result computed under it, adopting
    /// ownership of the sealed key and of the result's IV, ciphertext and tag — the result itself is not
    /// disposed by the caller after this returns.
    /// </summary>
    /// <param name="sealedKey">The sealed content key.</param>
    /// <param name="encrypted">The AEAD result whose carriers this envelope takes over.</param>
    /// <returns>The envelope.</returns>
    internal static TpmSealedEnvelope FromEncryption(TpmSealedBlob sealedKey, AeadEncryptResult encrypted) =>
        new(sealedKey, encrypted.Iv, encrypted.Tag, encrypted.Ciphertext);

    /// <summary>
    /// Serializes <paramref name="sealedKey"/> into the octets the AEAD binds the ciphertext to as its
    /// additional authenticated data — the same octets <see cref="WriteTo"/> writes first.
    /// </summary>
    /// <param name="sealedKey">The sealed content key.</param>
    /// <param name="pool">The memory pool backing the serialized octets.</param>
    /// <returns>The serialized sealed key as additional authenticated data; the caller owns and disposes it.</returns>
    internal static AdditionalData SerializeAsAdditionalData(TpmSealedBlob sealedKey, BaseMemoryPool pool)
    {
        int size = sealedKey.GetSerializedSize();
        IMemoryOwner<byte> owner = pool.Rent(size);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..size]);
            sealedKey.WriteTo(ref writer);

            return new AdditionalData(owner, CryptoTags.AesGcmAad);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Serializes this envelope's <see cref="SealedKey"/> into the additional authenticated data the ciphertext
    /// was bound to.
    /// </summary>
    /// <param name="pool">The memory pool backing the serialized octets.</param>
    /// <returns>The serialized sealed key as additional authenticated data; the caller owns and disposes it.</returns>
    internal AdditionalData SerializeSealedKeyAsAdditionalData(BaseMemoryPool pool)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);

        return SerializeAsAdditionalData(SealedKey, pool);
    }

    /// <summary>
    /// Releases the pooled storage backing <see cref="SealedKey"/>, <see cref="Iv"/>, <see cref="Tag"/> and
    /// <see cref="Ciphertext"/>.
    /// </summary>
    public void Dispose()
    {
        if(!isDisposed)
        {
            SealedKey.Dispose();
            Iv.Dispose();
            Tag.Dispose();
            Ciphertext.Dispose();
            isDisposed = true;
        }
    }

    /// <summary>Reads one <c>UINT16</c>-prefixed field into its own pooled storage.</summary>
    /// <param name="reader">The reader positioned at the length prefix.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The field's octets in pooled storage; the caller owns it.</returns>
    private static IMemoryOwner<byte> ReadSized(ref TpmReader reader, BaseMemoryPool pool)
    {
        ushort length = reader.ReadUInt16();

        return Copy(reader.ReadBytes(length), pool);
    }

    /// <summary>Copies <paramref name="octets"/> into pooled storage of exactly their width.</summary>
    /// <param name="octets">The octets to copy.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The pooled copy; the caller owns it.</returns>
    private static IMemoryOwner<byte> Copy(ReadOnlySpan<byte> octets, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(octets.Length);
        octets.CopyTo(owner.Memory.Span);

        return owner;
    }

    /// <summary>The debugger view: widths only, never the key or the ciphertext octets.</summary>
    private string DebuggerDisplay => $"TpmSealedEnvelope(ciphertext={Ciphertext.AsReadOnlySpan().Length} bytes, sealed key private={SealedKey.OutPrivate.Length} bytes)";
}
