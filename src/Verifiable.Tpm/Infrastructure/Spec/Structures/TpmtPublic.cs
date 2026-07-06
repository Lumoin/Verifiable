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

        return sizeof(ushort) +                 //Type.
               sizeof(ushort) +                 //NameAlg.
               sizeof(uint) +                   //ObjectAttributes.
               AuthPolicy.SerializedSize + //AuthPolicy (TPM2B_DIGEST).
               Parameters.SerializedSize +
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
        try
        {
            var parameters = TpmuPublicParms.Parse(type, ref reader);
            var unique = TpmuPublicId.Parse(type, ref reader, pool);

            return new TpmtPublic(type, nameAlg, objectAttributes, authPolicy, parameters, unique);
        }
        catch
        {
            //An unmodelled public-area type makes the parms/unique union arm throw; the pooled, policy-sensitive
            //authPolicy digest already rented above must be returned to the pool rather than leaked.
            authPolicy.Dispose();
            throw;
        }
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
    /// Creates a public area for a generated ECC signing key: an ECC signing public area carrying the key's
    /// actual public point — the form a TPM returns in <c>outPublic</c>, as opposed to the empty-unique template
    /// a caller supplies in <c>inPublic</c> (<see cref="CreateEccSigningTemplate"/>).
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="curve">ECC curve.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned public area.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to re-emit into the exported public area, or empty (default) for none.</param>
    /// <returns>The public area.</returns>
    public static TpmtPublic CreateEccSigningKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme,
        TpmsEccPoint unique,
        MemoryPool<byte> pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        ArgumentNullException.ThrowIfNull(unique);
        ArgumentNullException.ThrowIfNull(pool);

        TpmuPublicParms parameters = TpmuPublicParms.Ecc(TpmsEccParms.ForSigning(curve, scheme));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            TpmuPublicId.FromEccPoint(unique));
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
    /// Creates a public area for a generated RSA signing key: an RSA signing public area carrying the key's actual
    /// public modulus — the form a TPM returns in <c>outPublic</c>, as opposed to the empty-unique template a
    /// caller supplies in <c>inPublic</c> (<see cref="CreateRsaSigningTemplate"/>).
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes.</param>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">Signing scheme.</param>
    /// <param name="modulus">The generated public modulus (big-endian); copied into pooled storage the returned area owns.</param>
    /// <param name="pool">The memory pool for the modulus storage and the authPolicy digest.</param>
    /// <param name="authPolicy">The authorization policy digest to re-emit into the exported public area, or empty (default) for none.</param>
    /// <returns>The public area.</returns>
    public static TpmtPublic CreateRsaSigningKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        TpmtRsaScheme scheme,
        ReadOnlySpan<byte> modulus,
        MemoryPool<byte> pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmuPublicParms parameters = TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(keyBits, scheme));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_RSA,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            TpmuPublicId.FromRsaModulus(modulus, pool));
    }

    
    /// <summary>
    /// Creates a public area template for an ECC ECDH key agreement key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The key attributes are:
    /// </para>
    /// <list type="bullet">
    ///   <item><description><see cref="TpmaObject.FIXED_TPM"/>: Key hierarchy is fixed.</description></item>
    ///   <item><description><see cref="TpmaObject.FIXED_PARENT"/>: Parent is fixed.</description></item>
    ///   <item><description><see cref="TpmaObject.SENSITIVE_DATA_ORIGIN"/>: TPM generates all sensitive data.</description></item>
    ///   <item><description><see cref="TpmaObject.USER_WITH_AUTH"/>: USER role actions may be approved with password.</description></item>
    ///   <item><description><see cref="TpmaObject.DECRYPT"/>: Key is used for ECDH key agreement (TPM's term for key agreement).</description></item>
    /// </list>
    /// </remarks>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve.</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateEccKeyAgreementTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve)
    {
        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.DECRYPT;

        TpmuPublicParms parameters = TpmuPublicParms.Ecc(TpmsEccParms.ForKeyAgreement(curve));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Empty,
            parameters,
            TpmuPublicId.EmptyEcc());
    }

    /// <summary>
    /// Creates a public area template for an ECC restricted storage key, the kind of key that can act as
    /// a parent for <c>TPM2_Create()</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A parent must be a restricted decryption (storage) key with a symmetric definition: it wraps the
    /// sensitive area of its children under that symmetric key. The attributes are:
    /// </para>
    /// <list type="bullet">
    ///   <item><description><see cref="TpmaObject.FIXED_TPM"/> / <see cref="TpmaObject.FIXED_PARENT"/>: the key is non-duplicable.</description></item>
    ///   <item><description><see cref="TpmaObject.SENSITIVE_DATA_ORIGIN"/>: the TPM generates the sensitive data.</description></item>
    ///   <item><description><see cref="TpmaObject.USER_WITH_AUTH"/>: USER-role actions may be authorized with the authValue.</description></item>
    ///   <item><description><see cref="TpmaObject.RESTRICTED"/> + <see cref="TpmaObject.DECRYPT"/>: a storage parent (TPM 2.0 Part 1, Section 25.2).</description></item>
    /// </list>
    /// </remarks>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the key do not advance the dictionary-attack lockout counter.</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateEccStorageParentTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve,
        bool noDa = false)
    {
        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.RESTRICTED |
            TpmaObject.DECRYPT;

        if(noDa)
        {
            objectAttributes |= TpmaObject.NO_DA;
        }

        TpmuPublicParms parameters = TpmuPublicParms.Ecc(
            TpmsEccParms.ForStorage(curve, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Empty,
            parameters,
            TpmuPublicId.EmptyEcc());
    }

    /// <summary>
    /// Creates a public area for a generated ECC restricted storage key, carrying the key's actual public point —
    /// the form a TPM returns in <c>outPublic</c> for a storage primary, as opposed to the empty-unique template a
    /// caller supplies in <c>inPublic</c> (<see cref="CreateEccStorageParentTemplate"/>). The symmetric definition
    /// (AES-128-CFB) matches the template so the object round-trips identically apart from the populated point.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (a storage parent: RESTRICTED + DECRYPT).</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned public area.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">
    /// The authorization policy digest to re-emit into the exported public area (for example a standard
    /// endorsement key's "PolicyA", <see cref="CreateEccEndorsementKeyTemplate"/>), or empty (default) for none.
    /// </param>
    /// <returns>The public area.</returns>
    public static TpmtPublic CreateEccStorageParent(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmsEccPoint unique,
        MemoryPool<byte> pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        ArgumentNullException.ThrowIfNull(unique);
        ArgumentNullException.ThrowIfNull(pool);

        TpmuPublicParms parameters = TpmuPublicParms.Ecc(
            TpmsEccParms.ForStorage(curve, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            TpmuPublicId.FromEccPoint(unique));
    }

    /// <summary>
    /// Creates a public area template for the standard ECC NIST P-256 endorsement key (TCG EK Credential Profile,
    /// Annex B.3.4, Template L-2): a restricted storage key whose USER-role authorization is gated on a policy
    /// session over the Endorsement Hierarchy's authorization ("PolicyA") rather than on the object's own authValue.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attributes are <see cref="TpmaObject.FIXED_TPM"/> | <see cref="TpmaObject.FIXED_PARENT"/> |
    /// <see cref="TpmaObject.SENSITIVE_DATA_ORIGIN"/> | <see cref="TpmaObject.ADMIN_WITH_POLICY"/> |
    /// <see cref="TpmaObject.RESTRICTED"/> | <see cref="TpmaObject.DECRYPT"/>. <see cref="TpmaObject.USER_WITH_AUTH"/>
    /// is deliberately CLEAR — USER-role actions on the key (for example <c>TPM2_ActivateCredential()</c>'s
    /// <c>keyHandle</c>) require a policy session satisfying <paramref name="authPolicy"/> — and
    /// <see cref="TpmaObject.NO_DA"/> is deliberately CLEAR: TCG EK Credential Profile, Annex B.3.1 states the EK
    /// stays dictionary-attack protected because it is privacy sensitive.
    /// </para>
    /// <para>
    /// The symmetric definition is AES-128-CFB with a NULL scheme, the same combination
    /// <see cref="CreateEccStorageParentTemplate"/> uses (TCG EK Credential Profile, Annex B.3.4, Table 3).
    /// </para>
    /// <para>
    /// <paramref name="authPolicy"/> is the caller-computed "PolicyA" digest (TCG EK Credential Profile, Annex
    /// B.6.2: <c>H(H(0{32} ‖ TPM_CC_PolicySecret ‖ TPM_RH_ENDORSEMENT))</c>, reproduced by
    /// <see cref="Verifiable.Tpm.Infrastructure.TpmPolicyDigest.ExtendForSecret"/>), copied into pooled storage the
    /// returned area owns and disposes — the same authPolicy-storage shape <see cref="CreateSealedDataTemplate"/> uses.
    /// </para>
    /// <para>
    /// <c>unique</c> is a <b>present</b>, all-zero 32+32-octet ECC point rather than the zero-length template shape
    /// <see cref="TpmuPublicId.EmptyEcc"/> produces: TCG EK Credential Profile, Annex B.3.1 requires "the buffer
    /// reserved for the public key of the EK is set to all zeros", so the template's serialized size already
    /// matches the size the generated key's public area will carry.
    /// </para>
    /// </remarks>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="curve">The ECC curve (<see cref="TpmEccCurveConstants.TPM_ECC_NIST_P256"/> for Template L-2).</param>
    /// <param name="pool">The memory pool backing the authPolicy digest and the all-zero unique point.</param>
    /// <param name="authPolicy">The 32-octet "PolicyA" digest (SHA-256 nameAlg).</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateEccEndorsementKeyTemplate(
        TpmAlgIdConstants nameAlg,
        TpmEccCurveConstants curve,
        MemoryPool<byte> pool,
        ReadOnlySpan<byte> authPolicy)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.ADMIN_WITH_POLICY |
            TpmaObject.RESTRICTED |
            TpmaObject.DECRYPT;

        TpmuPublicParms parameters = TpmuPublicParms.Ecc(
            TpmsEccParms.ForStorage(curve, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)));

        //TCG EK Credential Profile, Annex B.3.1: the public-key buffer is present and all zero, not the
        //zero-length TpmuPublicId.EmptyEcc() shape a caller-supplied signing/storage template ordinarily uses.
        Span<byte> zeroCoordinate = stackalloc byte[32];
        TpmuPublicId unique = TpmuPublicId.FromEccPoint(TpmsEccPoint.Create(zeroCoordinate, zeroCoordinate, pool));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            unique);
    }

    /// <summary>
    /// Creates a public area template for a sealed data object: a KEYEDHASH object with the null scheme whose
    /// sensitive area is caller-supplied data rather than a TPM-generated key. Sealing binds a secret to the
    /// TPM so only this TPM, under the named parent, can recover it with <c>TPM2_Unseal()</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attributes are <see cref="TpmaObject.FIXED_TPM"/> | <see cref="TpmaObject.FIXED_PARENT"/> |
    /// <see cref="TpmaObject.USER_WITH_AUTH"/>: the object is non-duplicable and bound to its parent (only this
    /// TPM can unseal it), and a USER-role action (the unseal) may be authorized with the object's authValue.
    /// </para>
    /// <para>
    /// <see cref="TpmaObject.SENSITIVE_DATA_ORIGIN"/> is deliberately absent — the caller supplies the data, the
    /// TPM does not originate it — and neither <see cref="TpmaObject.SIGN_ENCRYPT"/> nor
    /// <see cref="TpmaObject.DECRYPT"/> is set, because a sealed object is unsealed rather than used as a key.
    /// </para>
    /// <para>
    /// Supply <paramref name="authPolicy"/> to gate the unseal on a policy — for example a <c>TPM2_PolicyPCR</c>
    /// digest, which binds the unseal to platform state ("tie to this computer <i>and</i> this state"): a left
    /// empty (default) the object is authorized by its authValue alone. The digest is copied into pooled storage
    /// the returned area owns and disposes.
    /// </para>
    /// <para>
    /// By default the object is dictionary-attack protected, so failed unseal authorizations against a
    /// PIN-protected seal advance the TPM lockout counter. Set <paramref name="noDa"/> for a seal whose
    /// authValue is empty (nothing to brute-force), which also avoids the dictionary-attack bookkeeping a
    /// DA-protected entity incurs on its first authorization after a TPM reset.
    /// </para>
    /// <para>
    /// Specification reference: TPM 2.0 Library Part 1, Section 24 (Sealed Data); Part 3, Section 12.1 / 12.7.
    /// </para>
    /// </remarks>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to bind the object to, or empty (default) for none.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the sealed object do not advance the dictionary-attack lockout counter.</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateSealedDataTemplate(
        TpmAlgIdConstants nameAlg,
        MemoryPool<byte> pool,
        ReadOnlySpan<byte> authPolicy = default,
        bool noDa = false)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.USER_WITH_AUTH;

        if(noDa)
        {
            objectAttributes |= TpmaObject.NO_DA;
        }

        TpmuPublicParms parameters = TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.SealedData);

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            TpmuPublicId.EmptyKeyedHash());
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
