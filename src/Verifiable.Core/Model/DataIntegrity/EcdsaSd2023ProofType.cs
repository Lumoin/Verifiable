namespace Verifiable.Core.Model.DataIntegrity;


/// <summary>
/// Identifies the type of an ecdsa-sd-2023 proof.
/// </summary>
public enum EcdsaSd2023ProofType
{
    /// <summary>
    /// Unknown or invalid proof type.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Base proof created by the issuer.
    /// </summary>
    Base = 1,

    /// <summary>
    /// Derived proof created by the holder.
    /// </summary>
    Derived = 2
}