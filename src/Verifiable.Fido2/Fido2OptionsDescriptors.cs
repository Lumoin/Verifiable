using System.Collections.Generic;

namespace Verifiable.Fido2;

/// <summary>
/// The <see cref="Fido2CredentialRecord"/> → <see cref="PublicKeyCredentialDescriptor"/> projection
/// shared by <see cref="Fido2RegistrationOptionsBuilder"/>'s <c>excludeCredentials</c> default and
/// <see cref="Fido2AssertionOptionsBuilder"/>'s <c>allowCredentials</c> default.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-credential-descriptor">W3C Web
/// Authentication Level 3, section 5.8.3: Credential Descriptor</see> — rows 4270 (descriptor
/// <c>type</c> SHOULD mirror the record's own <c>type</c>), 4277 (<c>id</c> SHOULD mirror the
/// record's own <c>id</c>) and 4285 (<c>transports</c> SHOULD mirror the record's own
/// <c>transports</c>). A single mechanical mapper closes all three rows for both option dictionaries
/// at once.
/// </remarks>
internal static class Fido2OptionsDescriptors
{
    /// <summary>
    /// Projects every supplied <see cref="Fido2CredentialRecord"/> into a
    /// <see cref="PublicKeyCredentialDescriptor"/>, mirroring its <c>type</c>/<c>id</c>/<c>transports</c>
    /// verbatim.
    /// </summary>
    /// <param name="records">
    /// The credential records to project, or <see langword="null"/> when the caller supplied none.
    /// </param>
    /// <returns>
    /// One descriptor per record, in the same order, or an empty list (never <see langword="null"/>)
    /// when <paramref name="records"/> is <see langword="null"/> or empty — matching the CR's own
    /// <c>[]</c> default for both <c>excludeCredentials</c> and <c>allowCredentials</c>.
    /// </returns>
    public static IReadOnlyList<PublicKeyCredentialDescriptor> ProjectDescriptors(IReadOnlyList<Fido2CredentialRecord>? records)
    {
        if(records is null || records.Count == 0)
        {
            return [];
        }

        List<PublicKeyCredentialDescriptor> descriptors = new(records.Count);
        foreach(Fido2CredentialRecord record in records)
        {
            descriptors.Add(new PublicKeyCredentialDescriptor
            {
                Type = record.Type,
                Id = record.Id,
                Transports = record.Transports.Count > 0 ? record.Transports : null
            });
        }

        return descriptors;
    }
}
