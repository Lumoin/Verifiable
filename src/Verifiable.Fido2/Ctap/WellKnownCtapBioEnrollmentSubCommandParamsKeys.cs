namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorBioEnrollment</c> request's <c>subCommandParams</c>
/// member.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the <c>subCommandParams</c> fields
/// table (snapshot lines 6459-6483). Every field is Optional here — required-ness is per-subCommand
/// (for example <c>setFriendlyName</c>/<c>removeEnrollment</c> both require <see cref="TemplateId"/>),
/// not a structural property of this key vocabulary.
/// </remarks>
public static class WellKnownCtapBioEnrollmentSubCommandParamsKeys
{
    /// <summary>The <c>templateId</c> field (<c>0x01</c>): the template identifier a subcommand names.</summary>
    public const int TemplateId = 0x01;

    /// <summary>The <c>templateFriendlyName</c> field (<c>0x02</c>): the template's human-readable name.</summary>
    public const int TemplateFriendlyName = 0x02;

    /// <summary>The <c>timeoutMilliseconds</c> field (<c>0x03</c>): the platform's requested capture timeout.</summary>
    public const int TimeoutMilliseconds = 0x03;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="TemplateId"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>templateId</c> key.</returns>
    public static bool IsTemplateId(int key) => key == TemplateId;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="TemplateFriendlyName"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>templateFriendlyName</c> key.</returns>
    public static bool IsTemplateFriendlyName(int key) => key == TemplateFriendlyName;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="TimeoutMilliseconds"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>timeoutMilliseconds</c> key.</returns>
    public static bool IsTimeoutMilliseconds(int key) => key == TimeoutMilliseconds;
}
