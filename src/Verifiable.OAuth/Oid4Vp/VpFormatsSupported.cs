using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Maps credential format identifiers to their algorithm constraints, as defined
/// in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11.1">OID4VP 1.0 §11.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// Published in Wallet metadata at the well-known endpoint as
/// <c>vp_formats_supported</c> per §10.1, and passed inline in the JAR via
/// <c>client_metadata</c> as <c>vp_formats_supported</c> per §11.1. Fetched
/// and cached by the application using its own HTTP infrastructure and
/// <see cref="Verifiable.OAuth.WellKnownPaths"/>.
/// </para>
/// <para>
/// The outer dictionary key is a credential format identifier — see
/// <see cref="WellKnownCredentialFormats"/> for OID4VP-native and ISO format
/// identifiers, and
/// <see cref="Verifiable.JCose.WellKnownMediaTypes.Jwt.DcSdJwt"/> for
/// <c>dc+sd-jwt</c>. The inner dictionary maps format-specific property names
/// (see <see cref="Verifiable.OAuth.Oid4Vp.Formats.WellKnownDcSdJwtFormatProperties"/>,
/// <see cref="Verifiable.OAuth.Oid4Vp.Formats.WellKnownJwtVcFormatProperties"/>,
/// <see cref="Verifiable.OAuth.Oid4Vp.Formats.WellKnownMsoMdocFormatProperties"/>)
/// to lists of supported algorithm identifiers.
/// </para>
/// <para>
/// Decision logic such as <c>SupportsFormat</c> and <c>GetAlgorithms</c> is
/// provided by <see cref="VpFormatsExtensions"/> rather than on this type,
/// so the POCO remains thin and suitable for caching and delegation.
/// </para>
/// </remarks>
[DebuggerDisplay("VpFormatsSupported Count={Formats.Count}")]
public sealed class VpFormatsSupported
{
    /// <summary>
    /// The format support map. The outer key is a credential format identifier.
    /// The inner key is a format-specific algorithm property name. The value is
    /// the list of supported algorithm identifiers for that property.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<string>>> Formats { get; }


    /// <summary>
    /// Initializes a <see cref="VpFormatsSupported"/> from an existing map.
    /// </summary>
    public VpFormatsSupported(IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<string>>> formats)
    {
        ArgumentNullException.ThrowIfNull(formats);

        Formats = formats;
    }
}
