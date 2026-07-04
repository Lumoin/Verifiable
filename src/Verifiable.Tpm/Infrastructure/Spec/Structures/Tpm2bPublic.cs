using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Sized buffer containing a public area (TPM2B_PUBLIC).
/// </summary>
/// <remarks>
/// <para>
/// This structure wraps <see cref="TpmtPublic"/> with a size prefix.
/// It is used in commands like <c>TPM2_CreatePrimary()</c>, <c>TPM2_Create()</c>,
/// <c>TPM2_Load()</c>, and <c>TPM2_ReadPublic()</c>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of publicArea in bytes.
///     TPMT_PUBLIC publicArea;                  // The public area.
/// } TPM2B_PUBLIC;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.5, Table 220.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bPublic: IDisposable, ITpmWireType
{
    private readonly IMemoryOwner<byte>? rawStorage;
    private readonly int rawLength;
    private bool disposed;

    /// <summary>
    /// Gets the public area.
    /// </summary>
    public TpmtPublic PublicArea { get; }

    /// <summary>
    /// Initializes a new sized public buffer.
    /// </summary>
    private Tpm2bPublic(TpmtPublic publicArea, IMemoryOwner<byte>? rawStorage, int rawLength)
    {
        PublicArea = publicArea;
        this.rawStorage = rawStorage;
        this.rawLength = rawLength;
    }

    /// <summary>
    /// Gets the raw bytes of the public area (for Name computation).
    /// </summary>
    /// <returns>The raw public area bytes.</returns>
    /// <remarks>
    /// These bytes are used to compute the object's Name:
    /// Name = nameAlg || H_nameAlg(TPMT_PUBLIC bytes).
    /// </remarks>
    public ReadOnlySpan<byte> GetRawBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(rawStorage is null)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return rawStorage.Memory.Span.Slice(0, rawLength);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return sizeof(ushort) + PublicArea.GetSerializedSize();
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int innerSize = PublicArea.GetSerializedSize();
        writer.WriteUInt16((ushort)innerSize);
        PublicArea.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sized public buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed public buffer.</returns>
    public static Tpm2bPublic Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            throw new InvalidOperationException("TPM2B_PUBLIC size cannot be zero.");
        }

        // Read raw bytes for Name computation.
        IMemoryOwner<byte> rawStorage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(rawStorage.Memory.Span.Slice(0, size));

            // Parse the structure from the raw bytes.
            var innerReader = new TpmReader(rawStorage.Memory.Span.Slice(0, size));
            var publicArea = TpmtPublic.Parse(ref innerReader, pool);

            return new Tpm2bPublic(publicArea, rawStorage, size);
        }
        catch
        {
            //A short buffer or an unmodelled inner public area must not leak the pooled raw-bytes rental.
            rawStorage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a sized public buffer from a public area (for writing templates).
    /// </summary>
    /// <param name="publicArea">The public area.</param>
    /// <returns>The sized public buffer.</returns>
    /// <remarks>
    /// This method is used for writing templates to the TPM. The raw bytes
    /// are not stored (they can be computed if needed).
    /// </remarks>
    public static Tpm2bPublic FromTemplate(TpmtPublic publicArea)
    {
        return new Tpm2bPublic(publicArea, null, 0);
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for an ECC signing key template.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="curve">ECC curve.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccSigningTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme)
    {
        var publicArea = TpmtPublic.CreateEccSigningTemplate(nameAlg, objectAttributes, curve, scheme);
        return FromTemplate(publicArea);
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated ECC signing key, carrying the key's actual public point (the
    /// <c>outPublic</c> form), as opposed to the empty-unique template <see cref="CreateEccSigningTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="curve">ECC curve.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned buffer.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccSigningKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme,
        TpmsEccPoint unique)
    {
        return FromTemplate(TpmtPublic.CreateEccSigningKey(nameAlg, objectAttributes, curve, scheme, unique));
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for an RSA signing key template.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateRsaSigningTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        TpmtRsaScheme scheme)
    {
        var publicArea = TpmtPublic.CreateRsaSigningTemplate(nameAlg, objectAttributes, keyBits, scheme);
        return FromTemplate(publicArea);
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated RSA signing key, carrying the key's actual public modulus (the
    /// <c>outPublic</c> form), as opposed to the empty-unique template <see cref="CreateRsaSigningTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <param name="modulus">The generated public modulus (big-endian); copied into pooled storage the returned buffer owns.</param>
    /// <param name="pool">The memory pool for the modulus storage.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateRsaSigningKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        TpmtRsaScheme scheme,
        ReadOnlySpan<byte> modulus,
        MemoryPool<byte> pool)
    {
        return FromTemplate(TpmtPublic.CreateRsaSigningKey(nameAlg, objectAttributes, keyBits, scheme, modulus, pool));
    }


    /// <summary>
    /// Creates a sized public buffer template for an ECC ECDH key agreement key.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccKeyAgreementTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve)
    {
        return FromTemplate(TpmtPublic.CreateEccKeyAgreementTemplate(nameAlg, curve));
    }

    /// <summary>
    /// Creates a sized public buffer template for an ECC restricted storage key, suitable as the parent
    /// of <c>TPM2_Create()</c>.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the key do not advance the dictionary-attack lockout counter.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccStorageParentTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve,
        bool noDa = false)
    {
        return FromTemplate(TpmtPublic.CreateEccStorageParentTemplate(nameAlg, curve, noDa));
    }

    /// <summary>
    /// Creates a TPM2B_PUBLIC for a generated ECC restricted storage key, carrying the key's actual public point
    /// (the <c>outPublic</c> form), as opposed to the empty-unique template <see cref="CreateEccStorageParentTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (a storage parent: RESTRICTED + DECRYPT).</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned buffer.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateEccStorageParent(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmsEccPoint unique)
    {
        return FromTemplate(TpmtPublic.CreateEccStorageParent(nameAlg, objectAttributes, curve, unique));
    }

    /// <summary>
    /// Creates a sized public buffer template for a sealed data object (KEYEDHASH, null scheme), optionally
    /// gated on an authorization policy (for example a <c>TPM2_PolicyPCR</c> digest).
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to bind the object to, or empty (default) for none.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the sealed object do not advance the dictionary-attack lockout counter.</param>
    /// <returns>The sized public buffer.</returns>
    public static Tpm2bPublic CreateSealedDataTemplate(
        TpmAlgIdConstants nameAlg,
        MemoryPool<byte> pool,
        ReadOnlySpan<byte> authPolicy = default,
        bool noDa = false)
    {
        return FromTemplate(TpmtPublic.CreateSealedDataTemplate(nameAlg, pool, authPolicy, noDa));
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            PublicArea.Dispose();
            rawStorage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_PUBLIC({PublicArea.Type}, {rawLength} bytes)";
}
