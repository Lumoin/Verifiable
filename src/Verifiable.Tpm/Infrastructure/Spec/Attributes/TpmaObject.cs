using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_OBJECT - object attribute bits.
/// </summary>
/// <remarks>
/// <para>
/// Indicates an object's use, authorization types, and relationship to other objects. These attributes are set when the object is created
/// and are not changed by the TPM.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.3 (TPMA_OBJECT) and 8.3.3 (attribute descriptions).
/// </para>
/// </remarks>
[Flags]
public enum TpmaObject: uint
{
    /// <summary>
    /// FIXED_TPM (bit 1): SET (1) indicates the hierarchy of the object, as indicated by its Qualified Name, may not change.
    /// CLEAR (0) indicates the hierarchy may change as a result of this object or an ancestor being duplicated for use in another hierarchy.
    /// </summary>
    FIXED_TPM = 0x0000_0002,

    /// <summary>
    /// ST_CLEAR (bit 2): SET (1) indicates previously saved contexts of this object may not be loaded after Startup(CLEAR).
    /// CLEAR (0) indicates saved contexts may be used after Shutdown(STATE) and subsequent Startup().
    /// </summary>
    ST_CLEAR = 0x0000_0004,

    /// <summary>
    /// FIXED_PARENT (bit 4): SET (1) indicates the parent of the object may not change. CLEAR (0) indicates the parent may change
    /// as the result of a TPM2_Duplicate() of the object.
    /// </summary>
    FIXED_PARENT = 0x0000_0010,

    /// <summary>
    /// SENSITIVE_DATA_ORIGIN (bit 5): SET (1) indicates the TPM generated all sensitive data (other than authValue) at creation.
    /// CLEAR (0) indicates a portion of sensitive data (other than authValue) was provided by the caller.
    /// </summary>
    SENSITIVE_DATA_ORIGIN = 0x0000_0020,

    /// <summary>
    /// USER_WITH_AUTH (bit 6): SET (1) indicates USER role actions may be approved with an HMAC session, password (authValue),
    /// or a policy session. CLEAR (0) indicates USER role actions may only be approved with a policy session.
    /// </summary>
    USER_WITH_AUTH = 0x0000_0040,

    /// <summary>
    /// ADMIN_WITH_POLICY (bit 7): SET (1) indicates ADMIN role actions may only be approved with a policy session.
    /// CLEAR (0) indicates ADMIN role actions may be approved with an HMAC session, password (authValue), or a policy session.
    /// </summary>
    ADMIN_WITH_POLICY = 0x0000_0080,

    /// <summary>
    /// FIRMWARE_LIMITED (bit 8): SET (1) indicates the object exists only within a firmware-limited hierarchy.
    /// CLEAR (0) indicates the object can exist outside a firmware-limited hierarchy.
    /// </summary>
    FIRMWARE_LIMITED = 0x0000_0100,

    /// <summary>
    /// SVN_LIMITED (bit 9): SET (1) indicates the object exists only within an SVN-limited hierarchy.
    /// CLEAR (0) indicates the object can exist outside an SVN-limited hierarchy.
    /// </summary>
    SVN_LIMITED = 0x0000_0200,

    /// <summary>
    /// NO_DA (bit 10): SET (1) indicates the object is not subject to dictionary-attack protections.
    /// CLEAR (0) indicates the object is subject to dictionary-attack protections.
    /// </summary>
    NO_DA = 0x0000_0400,

    /// <summary>
    /// ENCRYPTED_DUPLICATION (bit 11): SET (1) indicates that if the object is duplicated, symmetricAlg shall not be TPM_ALG_NULL and
    /// newParentHandle shall not be TPM_RH_NULL. CLEAR (0) indicates the object may be duplicated without an inner wrapper and the new
    /// parent may be TPM_RH_NULL.
    /// </summary>
    ENCRYPTED_DUPLICATION = 0x0000_0800,

    /// <summary>
    /// RESTRICTED (bit 16): SET (1) indicates key usage is restricted to manipulate structures of known format and the parent of this key
    /// shall have RESTRICTED set. CLEAR (0) indicates key usage is not restricted to special formats.
    /// </summary>
    RESTRICTED = 0x0001_0000,

    /// <summary>
    /// DECRYPT (bit 17): SET (1) indicates the private portion of the key may be used to decrypt. CLEAR (0) indicates it may not be used to decrypt.
    /// </summary>
    DECRYPT = 0x0002_0000,

    /// <summary>
    /// SIGN_ENCRYPT (bit 18): SET (1) indicates: for an asymmetric cipher object, the private portion may be used to encrypt; for other objects,
    /// the private portion may be used to sign. CLEAR (0) indicates it may not be used to sign or encrypt.
    /// </summary>
    SIGN_ENCRYPT = 0x0004_0000,

    /// <summary>
    /// X509SIGN (bit 19): SET (1) indicates an asymmetric key that may not be used to sign with TPM2_Sign().
    /// CLEAR (0) indicates a key that may be used with TPM2_Sign() if SIGN_ENCRYPT is set.
    /// </summary>
    /// <remarks>
    /// Added in version 1.59. Only significant if SIGN_ENCRYPT is set.
    /// </remarks>
    X509SIGN = 0x0008_0000
}
