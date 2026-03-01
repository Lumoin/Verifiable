using System;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Selects the .NET type to instantiate for a given service <c>type</c> discriminator string.
/// The returned type must derive from <see cref="Service"/>.
/// </summary>
/// <param name="serviceType">The value of the <c>type</c> property from the JSON service entry.</param>
/// <returns>
/// A <see cref="Type"/> that derives from <see cref="Service"/>. Returning <c>typeof(Service)</c>
/// is the safe fallback for unknown types.
/// </returns>
/// <remarks>
/// <para>
/// The default implementation returns <c>typeof(Service)</c> for all inputs, preserving
/// any additional data in the <see cref="Service.AdditionalData"/> dictionary. Library users
/// wrap the default to add their own subclass mappings:
/// </para>
/// <code>
/// var defaultSelector = ServiceTypeSelectors.Default;
/// ServiceTypeSelector mySelector = serviceType => serviceType switch
/// {
///     "IdentityResolverService" => typeof(UntpIdentityResolverService),
///     "DIDCommMessaging" => typeof(DIDCommService),
///     _ => defaultSelector(serviceType)
/// };
/// </code>
/// </remarks>
public delegate Type ServiceTypeSelector(string serviceType);

/// <summary>
/// Selects the .NET type to instantiate for a given verification method <c>type</c> discriminator string.
/// The returned type must derive from <see cref="VerificationMethod"/>.
/// </summary>
/// <param name="verificationMethodType">
/// The value of the <c>type</c> property from the JSON verification method entry.
/// </param>
/// <returns>
/// A <see cref="Type"/> that derives from <see cref="VerificationMethod"/>. Returning
/// <c>typeof(VerificationMethod)</c> is the safe fallback for unknown types.
/// </returns>
/// <remarks>
/// <para>
/// The default implementation returns <c>typeof(VerificationMethod)</c> for all inputs.
/// Library users wrap the default to add subclasses that carry additional properties
/// as permitted by CID 1.1 ("A verification method MAY include additional properties"):
/// </para>
/// <code>
/// var defaultSelector = VerificationMethodTypeSelectors.Default;
/// VerificationMethodTypeSelector mySelector = vmType => vmType switch
/// {
///     "EcdsaSecp256k1RecoveryMethod2020" => typeof(EcdsaSecp256k1RecoveryMethod),
///     _ => defaultSelector(vmType)
/// };
/// </code>
/// <para>
/// This delegate is shared across all converters that deserialize verification methods,
/// including DID document and Data Integrity proof converters, ensuring consistent type
/// dispatch.
/// </para>
/// </remarks>
public delegate Type VerificationMethodTypeSelector(string verificationMethodType);

/// <summary>
/// Pre-built type selectors for common cases.
/// </summary>
public static class ServiceTypeSelectors
{
    /// <summary>
    /// Returns <c>typeof(Service)</c> for all inputs. Additional data is preserved
    /// in the <see cref="Service.AdditionalData"/> dictionary.
    /// </summary>
    public static ServiceTypeSelector Default { get; } = _ => typeof(Service);
}

/// <summary>
/// Pre-built type selectors for common cases.
/// </summary>
public static class VerificationMethodTypeSelectors
{
    /// <summary>
    /// Returns <c>typeof(VerificationMethod)</c> for all inputs. Additional data is
    /// preserved through the manual parse in the converter.
    /// </summary>
    public static VerificationMethodTypeSelector Default { get; } = _ => typeof(VerificationMethod);
}