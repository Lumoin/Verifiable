using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Transmitter-side checks for the CAEP Interoperability Profile 1.0: the
/// <c>events</c> claim MUST contain only one event, the event MUST be one of
/// the profile's three use-case types (<c>session-revoked</c>,
/// <c>credential-change</c>, <c>device-compliance-change</c>) with its REQUIRED
/// event-specific claims present and valid, and a Transmitter MUST populate
/// <c>reason_admin</c> with a non-empty object.
/// </summary>
/// <remarks>
/// These are profile checks layered over the base CAEP event definitions —
/// the base spec leaves <c>reason_admin</c> optional and does not bound the
/// event count. Receivers stay tolerant; this gate is for what a conforming
/// Transmitter emits.
/// </remarks>
public static class CaepInteropProfile
{
    /// <summary>
    /// Whether <paramref name="securityEvent"/> is one a conforming Transmitter
    /// may emit: a profile use-case event whose REQUIRED claims project and
    /// whose <c>reason_admin</c> is a non-empty object.
    /// </summary>
    public static bool IsConformantTransmitterEvent(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        CaepEventClaims? common = securityEvent.EventType switch
        {
            _ when CaepEventTypes.IsSessionRevoked(securityEvent.EventType) =>
                CaepSessionRevokedEvent.From(securityEvent)?.Common,
            _ when CaepEventTypes.IsCredentialChange(securityEvent.EventType) =>
                CaepCredentialChangeEvent.From(securityEvent)?.Common,
            _ when CaepEventTypes.IsDeviceComplianceChange(securityEvent.EventType) =>
                CaepDeviceComplianceChangeEvent.From(securityEvent)?.Common,
            _ => null
        };

        return common is { ReasonAdmin.Count: > 0 };
    }


    /// <summary>
    /// Whether <paramref name="token"/> is one a conforming Transmitter may
    /// emit: exactly one event, and that event passes
    /// <see cref="IsConformantTransmitterEvent"/>.
    /// </summary>
    public static bool IsConformantTransmitterToken(SecurityEventToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        return token.Events.Count == 1 && IsConformantTransmitterEvent(token.Events[0]);
    }


    /// <summary>
    /// Whether <paramref name="configuration"/> is a Transmitter Configuration Metadata document a
    /// conforming Transmitter may publish under the CAEP Interoperability Profile 1.0 §2.3: every
    /// member the profile raises to MUST-include is present, <c>spec_version</c> is <c>1_0</c> or
    /// greater (§2.3.1), and <c>authorization_schemes</c> declares the OAuth 2.0 scheme (§2.3.7).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the receiver-side counterpart to the emit-path secure default: where the Shared
    /// Signals Framework 1.0 §7.1 leaves <c>spec_version</c> free, <c>delivery_methods_supported</c>
    /// RECOMMENDED and <c>authorization_schemes</c> OPTIONAL, the profile makes all three MUST-include
    /// and pins <c>spec_version</c> to <c>1_0</c>-or-greater and the OAuth 2.0 scheme URN. A Receiver
    /// uses this predicate to reject a metadata document that does not meet the profile floor before
    /// relying on it. It deliberately does NOT gate the subject-format (§2.5) or signature-algorithm
    /// (§2.6) requirements, which turn on open review comments — see
    /// <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">the
    /// CAEP Interoperability Profile 1.0, draft 01</see>, §2.5/§2.6 and the public-review window
    /// (this predicate covers only the mechanically-checkable §2.3 metadata surface).
    /// </para>
    /// <para>
    /// The <c>spec_version</c> comparison reads the leading <c>major_minor</c> numeric prefix (any
    /// SSF interoperability-draft <c>-ID<em>n</em></c> suffix is ignored for the ordering) and
    /// fails closed — an absent, empty, or unparseable value is not conformant.
    /// </para>
    /// </remarks>
    /// <param name="configuration">The parsed Transmitter Configuration Metadata under test.</param>
    /// <returns><see langword="true"/> when every §2.3 metadata MUST is met; otherwise <see langword="false"/>.</returns>
    public static bool IsConformantTransmitterConfiguration(SsfTransmitterConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return SpecVersionIsAtLeastOneZero(configuration.SpecVersion)
            && !string.IsNullOrEmpty(configuration.JwksUri)
            && !string.IsNullOrEmpty(configuration.ConfigurationEndpoint)
            && !string.IsNullOrEmpty(configuration.StatusEndpoint)
            && !string.IsNullOrEmpty(configuration.VerificationEndpoint)
            && configuration.DeliveryMethodsSupported is { Count: > 0 }
            && configuration.AuthorizationSchemes is { Count: > 0 } schemes
            && DeclaresOAuth2Scheme(schemes);

        static bool SpecVersionIsAtLeastOneZero(string? specVersion)
        {
            if(string.IsNullOrEmpty(specVersion))
            {
                return false;
            }

            ReadOnlySpan<char> numericPrefix = specVersion.AsSpan();
            int suffixStart = numericPrefix.IndexOf('-');
            if(suffixStart >= 0)
            {
                numericPrefix = numericPrefix[..suffixStart];
            }

            int separator = numericPrefix.IndexOf('_');
            if(separator <= 0 || separator == numericPrefix.Length - 1)
            {
                return false;
            }

            if(!int.TryParse(numericPrefix[..separator], out int major) || !int.TryParse(numericPrefix[(separator + 1)..], out int minor))
            {
                return false;
            }

            return major > 1 || (major == 1 && minor >= 0);
        }

        static bool DeclaresOAuth2Scheme(IReadOnlyList<SsfAuthorizationScheme> schemes)
        {
            for(int i = 0; i < schemes.Count; ++i)
            {
                if(string.Equals(schemes[i].SpecUrn, SsfMetadataParameterNames.AuthorizationSchemeSpecUrnOAuth2, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
