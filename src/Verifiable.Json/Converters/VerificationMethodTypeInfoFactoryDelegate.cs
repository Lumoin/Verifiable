using Verifiable.Core.Model.Did.CryptographicSuites;

namespace Verifiable.Json.Converters;

/// <summary>
/// Factory delegate for resolving verification method type names to
/// <see cref="VerificationMethodTypeInfo"/> instances.
/// </summary>
/// <param name="verificationMethodTypeName">
/// The verification method type name from the JSON <c>type</c> property.
/// </param>
/// <returns>The corresponding <see cref="VerificationMethodTypeInfo"/> instance.</returns>
public delegate VerificationMethodTypeInfo VerificationMethodTypeInfoFactoryDelegate(string verificationMethodTypeName);
