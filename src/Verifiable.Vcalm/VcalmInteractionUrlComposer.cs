using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Verifiable.Vcalm;

/// <summary>
/// Composes and validates the W3C VCALM 1.0 §3.7 interaction-bootstrapping artifacts a coordinator
/// shares with a remote system: the §3.7.1 interaction URL, the §3.7.2 QR-code bounds, and the §3.7.3
/// <c>interaction:</c> scheme string. The library EMITS the validated interaction URL and ENFORCES the
/// §3.7.2 length bounds — it does NOT render a QR image (that is the application's presentation /
/// imaging concern, layered over the URL these methods return).
/// </summary>
/// <remarks>
/// <para>
/// §3.7.1: the interaction URL MUST conform to the URL Standard and "contain an iuv query parameter
/// encoding the interaction URL version number, which MUST be 1 when using this version of this API".
/// It SHOULD be an HTTPS URL containing an interaction-specific identifier, SHOULD be opaque, and
/// SHOULD NOT carry information derivable from the §3.7.4 GET response in its query parameters — so the
/// composer puts ONLY the interaction id (in the path) and the version (the one required query
/// parameter) into the URL.
/// </para>
/// <para>
/// §2.1 / §3.7.1: the interaction URL lives on a COORDINATOR's Web origin, not the workflow service —
/// the coordinator's base URL is resolved through the host-generic endpoint-URI seam, so the
/// deployment owns where on its origin the interaction resource sits. The §3.7.4 endpoint that serves
/// the URL's GET response is <see cref="WellKnownVcalmEndpointNames.VcalmInteractionProtocols"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmInteractionUrlComposer")]
public static class VcalmInteractionUrlComposer
{
    /// <summary>
    /// The §3.7.1 interaction-URL version value: "which MUST be 1 when using this version of this API."
    /// Emitted as the value of the REQUIRED <c>iuv</c> query parameter.
    /// </summary>
    public const string InteractionUrlVersion = "1";

    /// <summary>
    /// The §3.7.2 SHOULD-NOT length advisory bound: "the length of the interaction URL … SHOULD NOT
    /// exceed 400 alphanumeric characters." A URL longer than this validates but carries an advisory.
    /// </summary>
    public const int QrAdvisoryLengthLimit = 400;

    /// <summary>
    /// The §3.7.2 MUST-NOT length bound: "and MUST NOT exceed 4,296 alphanumeric characters." A URL
    /// longer than this is a hard error — it cannot be expressed as a single QR code per ISO 18004.
    /// </summary>
    public const int QrMaximumLength = 4296;

    /// <summary>The §3.7.3 scheme prefix: <c>scheme = "interaction:" interaction-url</c>.</summary>
    public const string InteractionSchemePrefix = "interaction:";


    /// <summary>
    /// Composes the §3.7.1 interaction URL from a coordinator <paramref name="coordinatorBaseUrl"/>
    /// (the resolved interaction resource path on the coordinator's Web origin) and the
    /// interaction-specific <paramref name="interactionId"/>, appending ONLY the REQUIRED
    /// <c>iuv=1</c> query parameter. The base URL is expected to already address the interaction
    /// resource (e.g. <c>https://app.example/interactions/z8n38Dp7a</c>) — the composer adds the
    /// version query parameter, never re-derivable §3.7.4 data (§3.7.1 SHOULD-NOT).
    /// </summary>
    /// <param name="coordinatorBaseUrl">
    /// The coordinator-hosted interaction resource URL, WITHOUT the <c>iuv</c> query parameter. §3.7.1:
    /// SHOULD be HTTPS and opaque; the composer preserves whatever scheme / opacity the deployment's
    /// endpoint-URI resolver produced.
    /// </param>
    /// <param name="interactionId">
    /// The §3.7.1 interaction-specific identifier. Carried only to assert it is present in the
    /// resolved URL — the resolver is expected to have placed it in the path; the composer does not
    /// re-append it as a query parameter (§3.7.1 opacity / SHOULD-NOT).
    /// </param>
    /// <returns>The §3.7.1 interaction URL carrying <c>iuv=1</c>.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The coordinator base URL is the verbatim wire string the deployment's endpoint-URI resolver composed; round-tripping through System.Uri would normalize away the opacity §3.7.1 SHOULD prefers.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
        Justification = "The composed interaction URL is a verbatim wire string the §3.7.3 scheme wraps and the §3.7.2 length validator measures unchanged; returning System.Uri would normalize away the opacity §3.7.1 SHOULD prefers and re-encode the appended iuv parameter.")]
    public static string ComposeInteractionUrl(string coordinatorBaseUrl, string interactionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(coordinatorBaseUrl);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        //§3.7.1: the iuv query parameter is the one parameter the URL MUST carry. It is appended to the
        //resolved interaction resource URL — joined with '&' when the resolver already added a query,
        //else with '?'. The interaction id is expected in the path (§3.7.1 opacity / SHOULD-NOT puts no
        //GET-derivable data in the query), so it is not re-appended here.
        char separator = coordinatorBaseUrl.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        string iuvParameter = string.Create(
            CultureInfo.InvariantCulture, $"{VcalmParameterNames.Iuv}={InteractionUrlVersion}");

        return coordinatorBaseUrl + separator + iuvParameter;
    }


    /// <summary>
    /// Composes the §3.7.3 <c>interaction:</c> scheme string for an interaction URL —
    /// <c>scheme = "interaction:" interaction-url</c> — so an application can invoke software capable
    /// of processing the interaction URL. The §3.7.3 syntax prepends the literal <c>interaction:</c>
    /// scheme to the interaction URL with no other transformation.
    /// </summary>
    /// <param name="interactionUrl">
    /// The §3.7.1 interaction URL (carrying <c>iuv=1</c>) the scheme wraps. Retrieving the resource at
    /// the URL must result in a §3.7.4 interaction protocols response.
    /// </param>
    /// <returns>The §3.7.3 <c>interaction:&lt;interaction-url&gt;</c> scheme string.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The interaction URL is the verbatim §3.7.1 string this composer produced or the deployment supplied; the §3.7.3 scheme wraps it unparsed.")]
    public static string ComposeInteractionScheme(string interactionUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(interactionUrl);

        return InteractionSchemePrefix + interactionUrl;
    }


    /// <summary>
    /// Validates an interaction URL against the §3.7.2 QR-code length bounds. The library does NOT
    /// render the QR image (the §3.7.2 ISO-18004 encoding is the application's presentation concern); it
    /// validates the URL the QR would carry. A URL over the §3.7.2 <see cref="QrMaximumLength"/> hard
    /// bound is the MUST-NOT (the result is not valid); a URL over the
    /// <see cref="QrAdvisoryLengthLimit"/> advisory bound is the SHOULD-NOT (valid, with the advisory
    /// flag set so the deployment can shorten it).
    /// </summary>
    /// <param name="interactionUrl">The §3.7.1 interaction URL to validate.</param>
    /// <returns>
    /// The §3.7.2 validation outcome carrying the URL length, the hard-bound result, and the advisory
    /// flag.
    /// </returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The interaction URL is the verbatim §3.7.1 string being length-checked; System.Uri would not change the character count the §3.7.2 bounds constrain.")]
    public static VcalmInteractionQrValidation ValidateQrBounds(string interactionUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(interactionUrl);

        int length = interactionUrl.Length;

        //§3.7.2: "MUST NOT exceed 4,296 alphanumeric characters" — over the hard bound the URL cannot
        //be a single QR code, so it is invalid. "SHOULD NOT exceed 400 alphanumeric characters" — over
        //the advisory bound the URL is still valid but flagged so the deployment can shorten it.
        bool isWithinHardBound = length <= QrMaximumLength;
        bool isWithinAdvisoryBound = length <= QrAdvisoryLengthLimit;

        return new VcalmInteractionQrValidation
        {
            UrlLength = length,
            IsValid = isWithinHardBound,
            HasAdvisory = isWithinHardBound && !isWithinAdvisoryBound
        };
    }
}
