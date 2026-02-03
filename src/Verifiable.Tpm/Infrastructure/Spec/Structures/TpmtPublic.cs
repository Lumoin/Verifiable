using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Public area of a TPM object (TPMT_PUBLIC).
/// </summary>
/// <remarks>
/// <para>
/// This structure defines the public portion of a TPM object (key or data).
/// The Name of the object is computed as: Name = nameAlg || H_nameAlg(TPMT_PUBLIC).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_PUBLIC type;                    // Algorithm type (RSA, ECC, etc.).
///     TPMI_ALG_HASH nameAlg;                   // Hash algorithm for Name computation.
///     TPMA_OBJECT objectAttributes;            // Object attributes.
///     TPM2B_DIGEST authPolicy;                 // Authorization policy (empty = no policy).
///     TPMU_PUBLIC_PARMS parameters;            // Algorithm-specific parameters.
///     TPMU_PUBLIC_ID unique;                   // Unique identifier (public key).
/// } TPMT_PUBLIC;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.4, Table 219.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtPublic: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the algorithm type (RSA, ECC, KEYEDHASH, SYMCIPHER).
    /// </summary>
    public TpmAlgIdConstants Type { get; }

    /// <summary>
    /// Gets the hash algorithm used to compute the Name.
    /// </summary>
    public TpmAlgIdConstants NameAlg { get; }

    /// <summary>
    /// Gets the object attributes.
    /// </summary>
    public TpmaObject ObjectAttributes { get; }

    /// <summary>
    /// Gets the authorization policy digest.
    /// </summary>
    /// <remarks>
    /// Empty for objects without a policy. When set, authorization requires
    /// satisfying the policy in addition to any authValue.
    /// </remarks>
    public Tpm2bDigest AuthPolicy { get; }

    /// <summary>
    /// Gets the algorithm-specific parameters.
    /// </summary>
    public TpmuPublicParms Parameters { get; }

    /// <summary>
    /// Gets the unique identifier (public key material).
    /// </summary>
    public TpmuPublicId Unique { get; }

    /// <summary>
    /// Initializes a new public area.
    /// </summary>
    private TpmtPublic(
        TpmAlgIdConstants type,
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        Tpm2bDigest authPolicy,
        TpmuPublicParms parameters,
        TpmuPublicId unique)
    {
        Type = type;
        NameAlg = nameAlg;
        ObjectAttributes = objectAttributes;
        AuthPolicy = authPolicy;
        Parameters = parameters;
        Unique = unique;
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(ushort) +                 // type
               sizeof(ushort) +                 // nameAlg
               sizeof(uint) +                   // objectAttributes
               AuthPolicy.GetSerializedSize() + // authPolicy (TPM2B_DIGEST)
               Parameters.GetSerializedSize() +
               Unique.GetSerializedSize();
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)Type);
        writer.WriteUInt16((ushort)NameAlg);
        writer.WriteUInt32((uint)ObjectAttributes);
        AuthPolicy.WriteTo(ref writer);
        Parameters.WriteTo(ref writer);
        Unique.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a public area from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed public area.</returns>
    public static TpmtPublic Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        var type = (TpmAlgIdConstants)reader.ReadUInt16();
        var nameAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        var objectAttributes = (TpmaObject)reader.ReadUInt32();
        var authPolicy = Tpm2bDigest.Parse(ref reader, pool);
        var parameters = TpmuPublicParms.Parse(type, ref reader);
        var unique = TpmuPublicId.Parse(type, ref reader, pool);

        return new TpmtPublic(type, nameAlg, objectAttributes, authPolicy, parameters, unique);
    }

    /// <summary>
    /// Creates a public area for an ECC signing key template.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="curve">ECC curve.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateEccSigningTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme)
    {
        var parameters = TpmuPublicParms.Ecc(TpmsEccParms.ForSigning(curve, scheme));
        var unique = TpmuPublicId.EmptyEcc();

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Empty,
            parameters,
            unique);
    }

    /// <summary>
    /// Creates a public area for an RSA signing key template.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateRsaSigningTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        TpmtRsaScheme scheme)
    {
        var parameters = TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(keyBits, scheme));
        var unique = TpmuPublicId.EmptyRsa();

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_RSA,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Empty,
            parameters,
            unique);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            AuthPolicy.Dispose();
            Unique.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMT_PUBLIC({Type}, {NameAlg}, {ObjectAttributes})";
}