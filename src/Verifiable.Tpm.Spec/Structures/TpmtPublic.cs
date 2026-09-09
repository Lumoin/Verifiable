using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, clause 12.2.4, Table 235.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtPublic: IDisposable
{
    private bool Disposed { get; set; }

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
        ObjectDisposedException.ThrowIf(Disposed, this);

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
        ObjectDisposedException.ThrowIf(Disposed, this);

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
    public static TpmtPublic Parse(ref TpmReader reader, BaseMemoryPool pool)
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
        BaseMemoryPool pool,
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
    /// Creates a public area template for an unrestricted RSA decryption key — Table 228's own body shows an
    /// unrestricted signing key and an unrestricted decryption key sharing the identical NULL-symmetric shape
    /// (<see cref="TpmsRsaParms.ForUnrestrictedKey"/>), distinguished only by the object attributes and the
    /// scheme the caller supplies, so this is <see cref="CreateRsaSigningTemplate"/> under a name that reads
    /// correctly at its decrypt-key call sites. A NULL <paramref name="scheme"/> template is the raw-primitive
    /// form Table 228's own deprecation admits — "Support for TPM_ALG_NULL except for Storage Keys, and keys
    /// intended for use with the raw RSAEP/RSADP primitive, was deprecated in version 185. See Part 0." (TPM 2.0
    /// Library Part 2, clause 12.2.3.4, Table 228), the carve-out TPM 2.0 Library Part 0, clause 3.1.4.2 names.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">Object attributes (an unrestricted decryption key: DECRYPT set, RESTRICTED and SIGN_ENCRYPT clear).</param>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">The decryption scheme.</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateRsaDecryptKeyTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        TpmtRsaScheme scheme) => CreateRsaSigningTemplate(nameAlg, objectAttributes, keyBits, scheme);

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
        BaseMemoryPool pool,
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
    /// Creates a public area template for an unrestricted ECC decryption key usable with
    /// <c>TPM2_Encapsulate()</c> and <c>TPM2_Decapsulate()</c> — the KEM key admission gate of TPM 2.0
    /// Library Part 2, Table 229 (see <see cref="TpmsEccParms.ForKeyEncapsulation"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unlike <see cref="CreateEccKeyAgreementTemplate"/> and <see cref="CreateEccStorageParentTemplate"/>,
    /// this factory takes <paramref name="objectAttributes"/> as a parameter rather than fixing it — the
    /// same shape <see cref="CreateEccSigningTemplate"/> uses — so a caller can add
    /// <see cref="TpmaObject.NO_DA"/> without a second factory. The attributes a KEM key needs are:
    /// </para>
    /// <list type="bullet">
    ///   <item><description><see cref="TpmaObject.FIXED_TPM"/> / <see cref="TpmaObject.FIXED_PARENT"/>: the key is non-duplicable.</description></item>
    ///   <item><description><see cref="TpmaObject.SENSITIVE_DATA_ORIGIN"/>: the TPM generates the sensitive data.</description></item>
    ///   <item><description><see cref="TpmaObject.USER_WITH_AUTH"/>: USER-role actions may be authorized with the authValue.</description></item>
    ///   <item><description><see cref="TpmaObject.DECRYPT"/> alone — <b>not</b> <see cref="TpmaObject.RESTRICTED"/> and <b>not</b> <see cref="TpmaObject.SIGN_ENCRYPT"/>: Table 229's <c>kdf</c> field is admitted "if the key is an unrestricted decryption TPM_ALG_ECDH key" and refused with <c>TPM_RC_KDF</c> "in all other cases" — a restricted key is the clause 14.11 anti-oracle boundary TPM2_Decapsulate() itself enforces, so the template must not carry it.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (an unrestricted decryption key: DECRYPT set, RESTRICTED and SIGN_ENCRYPT clear).</param>
    /// <param name="curve">The ECC curve — the DHKEM's <c>curveID</c>.</param>
    /// <param name="kdfHashAlg">
    /// The HKDF hash algorithm — the DHKEM's KDF hash. A caller-built <c>inPublic</c> template has no other
    /// input for <c>scheme.details.ecdh.hashAlg</c>, so this factory passes <paramref name="kdfHashAlg"/> for
    /// both — the field is inert on the KEM path (Table 229) regardless of which value it carries.
    /// </param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateEccKemKeyTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmAlgIdConstants kdfHashAlg)
    {
        TpmuPublicParms parameters = TpmuPublicParms.Ecc(TpmsEccParms.ForKeyEncapsulation(curve, kdfHashAlg, kdfHashAlg));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Empty,
            parameters,
            TpmuPublicId.EmptyEcc());
    }

    /// <summary>
    /// Creates a public area for a generated ECC KEM key, carrying the key's actual public point — the form
    /// a TPM returns in <c>outPublic</c> for a primary usable with <c>TPM2_Encapsulate()</c> and
    /// <c>TPM2_Decapsulate()</c>, as opposed to the empty-unique template a caller supplies in
    /// <c>inPublic</c> (<see cref="CreateEccKemKeyTemplate"/>).
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (an unrestricted decryption key: DECRYPT set, RESTRICTED and SIGN_ENCRYPT clear).</param>
    /// <param name="curve">The ECC curve — the DHKEM's <c>curveID</c>.</param>
    /// <param name="schemeHashAlg">The <c>scheme.details.ecdh.hashAlg</c> the creating template carried — echoed unchanged (Part 3, clause 24.1.1), independently of <paramref name="kdfHashAlg"/>.</param>
    /// <param name="kdfHashAlg">The HKDF hash algorithm — the DHKEM's KDF hash.</param>
    /// <param name="unique">The generated public point; ownership transfers to the returned public area.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to re-emit into the exported public area, or empty (default) for none.</param>
    /// <returns>The public area.</returns>
    public static TpmtPublic CreateEccKemKey(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmEccCurveConstants curve,
        TpmAlgIdConstants schemeHashAlg,
        TpmAlgIdConstants kdfHashAlg,
        TpmsEccPoint unique,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        ArgumentNullException.ThrowIfNull(unique);
        ArgumentNullException.ThrowIfNull(pool);

        TpmuPublicParms parameters = TpmuPublicParms.Ecc(TpmsEccParms.ForKeyEncapsulation(curve, schemeHashAlg, kdfHashAlg));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_ECC,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            TpmuPublicId.FromEccPoint(unique));
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
    ///   <item><description><see cref="TpmaObject.RESTRICTED"/> + <see cref="TpmaObject.DECRYPT"/>: a storage parent (TPM 2.0 Library Part 1, clause 22.1.4 (Decrypt Attribute) and Table 33 in clause 22.1.5 (Uses)).</description></item>
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
    /// Creates a public area template for an RSA restricted storage key — the empty-unique <c>inPublic</c> a
    /// caller supplies to mint an ordinary (password-authorizable) RSA storage parent, the RSA counterpart of
    /// <see cref="CreateEccStorageParentTemplate"/> and the non-endorsement sibling of
    /// <see cref="CreateRsaEndorsementKeyTemplate"/>.
    /// </summary>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="keyBits">The RSA modulus size in bits.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the parent do not advance the dictionary-attack lockout counter.</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateRsaStorageParentTemplate(
        TpmAlgIdConstants nameAlg,
        ushort keyBits,
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

        TpmuPublicParms parameters = TpmuPublicParms.Rsa(
            TpmsRsaParms.ForStorage(keyBits, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_RSA,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Empty,
            parameters,
            TpmuPublicId.EmptyRsa());
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
        BaseMemoryPool pool,
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
    /// <see cref="CreateEccStorageParentTemplate"/> uses (TCG EK Credential Profile, Annex B.3.4, Table 1).
    /// </para>
    /// <para>
    /// <paramref name="authPolicy"/> is the caller-computed "PolicyA" digest (TCG EK Credential Profile, Annex
    /// B.6.2: <c>H(H(0{32} ‖ TPM_CC_PolicySecret ‖ TPM_RH_ENDORSEMENT))</c>, reproduced by the engine's
    /// <c>TpmPolicyDigest.ExtendForSecret</c>), copied into pooled storage the
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
        BaseMemoryPool pool,
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
    /// Creates a public area template for the standard RSA 2048 endorsement key (TCG EK Credential Profile,
    /// Annex B.3.3, Template L-1): the RSA counterpart of <see cref="CreateEccEndorsementKeyTemplate"/> — a
    /// restricted storage key whose USER-role authorization is gated on a policy session over the Endorsement
    /// Hierarchy's authorization ("PolicyA") rather than on the object's own authValue.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attributes are byte-identical to Template L-2's (<see cref="CreateEccEndorsementKeyTemplate"/>):
    /// <see cref="TpmaObject.FIXED_TPM"/> | <see cref="TpmaObject.FIXED_PARENT"/> |
    /// <see cref="TpmaObject.SENSITIVE_DATA_ORIGIN"/> | <see cref="TpmaObject.ADMIN_WITH_POLICY"/> |
    /// <see cref="TpmaObject.RESTRICTED"/> | <see cref="TpmaObject.DECRYPT"/> — <see cref="TpmaObject.USER_WITH_AUTH"/>
    /// and <see cref="TpmaObject.NO_DA"/> both deliberately CLEAR, for the same reasons Template L-2 clears them
    /// (TCG EK Credential Profile, Annex B.3.1).
    /// </para>
    /// <para>
    /// The symmetric definition is AES-128-CFB with a NULL scheme (TCG EK Credential Profile, Annex B.3.3, Table
    /// 2) — RSA-OAEP has no separate KDF-scheme field the way an ECC key agreement scheme does; the "KDF" is
    /// implicit in OAEP's own MGF1. The exponent is the wire literal <c>0</c> (TPM 2.0 Library Part 2, Table 228),
    /// meaning the TPM default 2^16+1 — never write <c>65537</c> into the template.
    /// </para>
    /// <para>
    /// <paramref name="authPolicy"/> is the same caller-computed "PolicyA" digest <see cref="CreateEccEndorsementKeyTemplate"/>
    /// takes (TCG EK Credential Profile, Annex B.3.2: PolicyA authorizes knowledge of the Endorsement Hierarchy's
    /// authorization, a property of the hierarchy — not of the protected key's algorithm — so L-1 and L-2 carry
    /// the byte-identical 32-octet digest), copied into pooled storage the returned area owns and disposes.
    /// </para>
    /// <para>
    /// <c>unique</c> is a <b>present</b>, all-zero <paramref name="keyBits"/>/8-octet RSA modulus buffer rather
    /// than the zero-length template shape <see cref="TpmuPublicId.EmptyRsa"/> produces (TCG EK Credential
    /// Profile, Annex B.3.1's "buffer reserved for the public key of the EK is set to all zeros" — trap: never
    /// the empty-RSA convention some signing-key factories in this codebase use).
    /// </para>
    /// </remarks>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="keyBits">The RSA modulus size in bits (2048 for Template L-1).</param>
    /// <param name="pool">The memory pool backing the authPolicy digest and the all-zero unique modulus.</param>
    /// <param name="authPolicy">The 32-octet "PolicyA" digest (SHA-256 nameAlg).</param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateRsaEndorsementKeyTemplate(
        TpmAlgIdConstants nameAlg,
        ushort keyBits,
        BaseMemoryPool pool,
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

        TpmuPublicParms parameters = TpmuPublicParms.Rsa(
            TpmsRsaParms.ForStorage(keyBits, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)));

        //TCG EK Credential Profile, Annex B.3.1: the public-key buffer is present and all zero, not the
        //zero-length TpmuPublicId.EmptyRsa() shape a caller-supplied signing/storage template ordinarily uses.
        Span<byte> zeroModulus = stackalloc byte[keyBits / 8];
        TpmuPublicId unique = TpmuPublicId.FromRsaModulus(zeroModulus, pool);

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_RSA,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            unique);
    }

    /// <summary>
    /// Creates a public area for a generated RSA restricted storage key, carrying the key's actual public
    /// modulus — the form a TPM returns in <c>outPublic</c> for a storage primary (including the standard RSA
    /// endorsement key), as opposed to the empty-unique template a caller supplies in <c>inPublic</c>. The RSA
    /// counterpart of <see cref="CreateEccStorageParent"/>.
    /// </summary>
    /// <param name="nameAlg">The hash algorithm for Name computation.</param>
    /// <param name="objectAttributes">The object attributes (a storage parent: RESTRICTED + DECRYPT).</param>
    /// <param name="keyBits">The RSA modulus size in bits.</param>
    /// <param name="modulus">The generated public modulus (big-endian); copied into pooled storage the returned area owns.</param>
    /// <param name="pool">The memory pool for the modulus storage and the authPolicy digest.</param>
    /// <param name="authPolicy">
    /// The authorization policy digest to re-emit into the exported public area (for example a standard RSA
    /// endorsement key's "PolicyA", <see cref="CreateRsaEndorsementKeyTemplate"/>), or empty (default) for none.
    /// </param>
    /// <returns>The public area.</returns>
    public static TpmtPublic CreateRsaStorageParent(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        ushort keyBits,
        ReadOnlySpan<byte> modulus,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmuPublicParms parameters = TpmuPublicParms.Rsa(
            TpmsRsaParms.ForStorage(keyBits, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_RSA,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            TpmuPublicId.FromRsaModulus(modulus, pool));
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
    /// Specification reference: TPM 2.0 Library Part 1, clause 8.6.3 (the Sealed Data Object note); Part 3, clause 12.1 / 12.7.
    /// </para>
    /// </remarks>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to bind the object to, or empty (default) for none.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the sealed object do not advance the dictionary-attack lockout counter.</param>
    /// <param name="userWithAuth">
    /// When <see langword="true"/> (the default), sets TPMA_OBJECT.userWithAuth so a USER-role action (such as
    /// <c>TPM2_Unseal()</c>) may be authorized by an HMAC session or password as well as a policy session; when
    /// <see langword="false"/>, only a policy session may authorize it (TPM 2.0 Library Part 2, clause 8.3.3;
    /// Part 3, clause 5.6, check 7.1).
    /// </param>
    /// <param name="isDuplicable">
    /// When <see langword="true"/>, leaves TPMA_OBJECT.fixedTPM and fixedParent CLEAR so the created object may
    /// later leave its parent through <c>TPM2_Duplicate()</c>; when <see langword="false"/> (the default), both
    /// are SET and the object is bound to its parent and TPM for life (TPM 2.0 Library Part 2, clause 8.3.2,
    /// Table 37; Part 1, Clause 20).
    /// </param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateSealedDataTemplate(
        TpmAlgIdConstants nameAlg,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default,
        bool noDa = false,
        bool userWithAuth = true,
        bool isDuplicable = false)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //A duplicable object carries fixedTPM and fixedParent CLEAR — the pair moves together, since a creation
        //template under a fixedTPM-SET parent must hold them equal (TPM 2.0 Library Part 2, clause 8.3.3.2).
        TpmaObject objectAttributes = isDuplicable
            ? default
            : TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT;

        if(userWithAuth)
        {
            objectAttributes |= TpmaObject.USER_WITH_AUTH;
        }

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
    /// Creates a public area template for an HMAC key: a KEYEDHASH object whose sensitive area is the caller's
    /// (or the TPM's own generated) key rather than sealed opaque data. Part 2, clause 8.3.3.14 identifies this
    /// shape — <c>TPM_ALG_KEYEDHASH</c> with the <c>sign</c> attribute SET — as an HMAC key, consumed by
    /// <c>TPM2_HMAC_Start()</c>/<c>TPM2_HMAC()</c> (an unrestricted key) or, restricted, by <c>TPM2_Sign()</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attributes always carry <see cref="TpmaObject.SIGN_ENCRYPT"/> (the HMAC key's <c>sign</c> attribute)
    /// with <see cref="TpmaObject.DECRYPT"/> CLEAR — an HMAC key never decrypts. <paramref name="isRestricted"/>
    /// gates <see cref="TpmaObject.RESTRICTED"/>: CLEAR (the default) yields an ordinary key usable with
    /// <c>TPM2_HMAC_Start()</c> and <c>TPM2_HMAC()</c> (TPM 2.0 Library Part 3, clauses 17.2 and 15.5, both of
    /// which reject a restricted key with <c>TPM_RC_ATTRIBUTES</c>); SET yields a restricted signing key whose
    /// HMAC may only be produced over data <c>TPM2_Sign()</c> itself certifies as safe.
    /// </para>
    /// <para>
    /// <paramref name="isSensitiveDataOrigin"/> gates <see cref="TpmaObject.SENSITIVE_DATA_ORIGIN"/>: SET (the
    /// default) for a TPM-generated key, so the caller's <c>TPM2B_SENSITIVE_CREATE.data</c> must be empty;
    /// CLEAR when the caller supplies the key octets themselves (<see cref="Tpm2bSensitiveCreate.ForHmacKey"/>).
    /// </para>
    /// <para>
    /// <paramref name="authPolicy"/>, <paramref name="noDa"/>, <paramref name="userWithAuth"/>, and
    /// <paramref name="isDuplicable"/> carry the same meaning as <see cref="CreateSealedDataTemplate"/>'s
    /// identically-named parameters (Part 2, clause 8.3.2, Table 37; clause 8.3.3).
    /// </para>
    /// <para>
    /// Specification reference: TPM 2.0 Library Part 2, clause 8.3.3.14; clause 12.2.3.3, Table 227 (the
    /// deprecation of TPM_ALG_NULL for a signing HMAC key); Part 3, clauses 15.5 and 17.2.
    /// </para>
    /// </remarks>
    /// <param name="nameAlg">Hash algorithm for Name computation.</param>
    /// <param name="hashAlg">The HMAC hash algorithm (TPMS_SCHEME_HMAC's <c>hashAlg</c>).</param>
    /// <param name="pool">The memory pool backing the authPolicy digest (used only when one is supplied).</param>
    /// <param name="authPolicy">The authorization policy digest to bind the object to, or empty (default) for none.</param>
    /// <param name="noDa">When <see langword="true"/>, sets TPMA_OBJECT.noDA so authorization failures against the key do not advance the dictionary-attack lockout counter.</param>
    /// <param name="userWithAuth">
    /// When <see langword="true"/> (the default), sets TPMA_OBJECT.userWithAuth so a USER-role action (such as
    /// <c>TPM2_HMAC()</c>) may be authorized by an HMAC session or password as well as a policy session; when
    /// <see langword="false"/>, only a policy session may authorize it (TPM 2.0 Library Part 2, clause 8.3.3;
    /// Part 3, clause 5.6, check 7.1).
    /// </param>
    /// <param name="isDuplicable">
    /// When <see langword="true"/>, leaves TPMA_OBJECT.fixedTPM and fixedParent CLEAR so the created key may
    /// later leave its parent through <c>TPM2_Duplicate()</c>; when <see langword="false"/> (the default), both
    /// are SET and the key is bound to its parent and TPM for life (TPM 2.0 Library Part 2, clause 8.3.2,
    /// Table 37; Part 1, Clause 20).
    /// </param>
    /// <param name="isRestricted">
    /// When <see langword="true"/>, sets TPMA_OBJECT.restricted, producing a restricted signing key rather than
    /// an ordinary HMAC key usable with <c>TPM2_HMAC_Start()</c>/<c>TPM2_HMAC()</c>; <see langword="false"/> is
    /// the default.
    /// </param>
    /// <param name="isSensitiveDataOrigin">
    /// When <see langword="true"/> (the default), sets TPMA_OBJECT.sensitiveDataOrigin for a TPM-generated key;
    /// set <see langword="false"/> when the caller supplies the key octets in <c>TPM2B_SENSITIVE_CREATE.data</c>.
    /// </param>
    /// <returns>The public area template.</returns>
    public static TpmtPublic CreateHmacKeyTemplate(
        TpmAlgIdConstants nameAlg,
        TpmAlgIdConstants hashAlg,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> authPolicy = default,
        bool noDa = false,
        bool userWithAuth = true,
        bool isDuplicable = false,
        bool isRestricted = false,
        bool isSensitiveDataOrigin = true)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //A duplicable object carries fixedTPM and fixedParent CLEAR — the pair moves together, since a creation
        //template under a fixedTPM-SET parent must hold them equal (TPM 2.0 Library Part 2, clause 8.3.3.2).
        TpmaObject objectAttributes = isDuplicable
            ? default
            : TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT;

        objectAttributes |= TpmaObject.SIGN_ENCRYPT;

        if(isRestricted)
        {
            objectAttributes |= TpmaObject.RESTRICTED;
        }

        if(isSensitiveDataOrigin)
        {
            objectAttributes |= TpmaObject.SENSITIVE_DATA_ORIGIN;
        }

        if(userWithAuth)
        {
            objectAttributes |= TpmaObject.USER_WITH_AUTH;
        }

        if(noDa)
        {
            objectAttributes |= TpmaObject.NO_DA;
        }

        TpmuPublicParms parameters = TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.Hmac(hashAlg));

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            parameters,
            TpmuPublicId.EmptyKeyedHash());
    }

    /// <summary>
    /// Creates a KEYEDHASH public area that echoes an exact attribute word and keyed-hash scheme, the form the
    /// simulator returns as <c>outPublic</c> from <c>TPM2_Create()</c> (TPM 2.0 Library Part 3, clause 12.1: the
    /// created object's public area is the input template with its <c>unique</c> filled in). Unlike
    /// <see cref="CreateHmacKeyTemplate"/> and <see cref="CreateSealedDataTemplate"/>, which compose the
    /// attribute word from boolean options, this preserves whatever attributes and scheme the caller supplied —
    /// so a sealed data object (scheme <c>TPM_ALG_NULL</c>) and an HMAC key (scheme <c>TPM_ALG_HMAC</c>, sign
    /// SET) each round-trip faithfully. The <c>unique</c> argument selects the form: empty yields the template a
    /// caller sends in <c>inPublic</c>, and a supplied digest yields the <c>outPublic</c> form — one factory
    /// serves both because a KEYEDHASH public area is otherwise byte-identical in the two, unlike ECC and RSA,
    /// whose key forms carry a structurally different <c>unique</c> and so have separate factories such as
    /// <see cref="CreateEccSigningKey"/>.
    /// </summary>
    /// <param name="nameAlg">The object's name algorithm.</param>
    /// <param name="objectAttributes">The exact <c>TPMA_OBJECT</c> attribute word.</param>
    /// <param name="scheme">The keyed-hash scheme (NULL for a data object, HMAC for a signing key).</param>
    /// <param name="authPolicy">The authorization policy digest.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="unique">The <c>unique</c> value to carry — <c>H_nameAlg(seedValue ‖ sensitive)</c> per Part 2, clause 12.2.3.1, equation (8); Part 1, clause 24.5.3.2, equation (48) — or empty for the template form a caller sends.</param>
    /// <returns>The KEYEDHASH public area.</returns>
    public static TpmtPublic CreateKeyedHashTemplate(
        TpmAlgIdConstants nameAlg,
        TpmaObject objectAttributes,
        TpmsKeyedHashParms scheme,
        ReadOnlySpan<byte> authPolicy,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> unique = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new TpmtPublic(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            nameAlg,
            objectAttributes,
            Tpm2bDigest.Create(authPolicy, pool),
            TpmuPublicParms.KeyedHash(scheme),
            TpmuPublicId.FromKeyedHashUnique(unique, pool));
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!Disposed)
        {
            AuthPolicy.Dispose();
            Unique.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMT_PUBLIC({Type}, {NameAlg}, {ObjectAttributes})";
}
