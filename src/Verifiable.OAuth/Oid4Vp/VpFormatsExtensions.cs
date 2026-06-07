using System.Diagnostics.CodeAnalysis;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Formats;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Extension methods providing decision logic over <see cref="VpFormatsSupported"/>.
/// </summary>
/// <remarks>
/// Keeping decision logic here rather than on <see cref="VpFormatsSupported"/>
/// itself allows the POCO to remain thin, wire-format-faithful, and freely
/// cacheable and delegatable.
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# 13 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class VpFormatsExtensions
{
    extension(VpFormatsSupported formats)
    {
        /// <summary>
        /// Returns <see langword="true"/> when the given credential format identifier
        /// is present in the supported formats map. Comparison is case-sensitive per
        /// OID4VP 1.0 Appendix B.
        /// </summary>
        public bool SupportsFormat(string formatId)
        {
            ArgumentNullException.ThrowIfNull(formatId);
            return formats.Formats.ContainsKey(formatId);
        }


        /// <summary>
        /// Returns the algorithm list for the given format identifier and property
        /// name, or <see langword="null"/> when either the format or property is absent.
        /// </summary>
        /// <param name="formatId">
        /// The credential format identifier. Use
        /// <see cref="WellKnownMediaTypes.Jwt.DcSdJwt"/> for <c>dc+sd-jwt</c> or
        /// <see cref="WellKnownCredentialFormats"/> for other formats.
        /// </param>
        /// <param name="propertyName">
        /// The format-specific algorithm property name. Use
        /// <see cref="WellKnownDcSdJwtFormatProperties"/>,
        /// <see cref="WellKnownJwtVcFormatProperties"/>, or
        /// <see cref="WellKnownMsoMdocFormatProperties"/> for well-known values.
        /// </param>
        public IReadOnlyList<string>? GetAlgorithms(string formatId, string propertyName)
        {
            ArgumentNullException.ThrowIfNull(formatId);
            ArgumentNullException.ThrowIfNull(propertyName);

            if(!formats.Formats.TryGetValue(formatId,
                out IReadOnlyDictionary<string, IReadOnlyList<string>>? props))
            {
                return null;
            }

            return props.TryGetValue(propertyName, out IReadOnlyList<string>? algs) ? algs : null;
        }


        /// <summary>
        /// Returns <see langword="true"/> when <c>dc+sd-jwt</c> is supported with
        /// the given SD-JWT signing algorithm. Checks
        /// <see cref="WellKnownDcSdJwtFormatProperties.SdJwtAlgValues"/>.
        /// </summary>
        public bool SupportsDcSdJwtWithAlgorithm(string algorithm)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            IReadOnlyList<string>? algs = formats.GetAlgorithms(
                WellKnownMediaTypes.Jwt.DcSdJwt,
                WellKnownDcSdJwtFormatProperties.SdJwtAlgValues);

            return algs is not null && algs.Contains(algorithm, StringComparer.Ordinal);
        }


        /// <summary>
        /// Returns <see langword="true"/> when <c>dc+sd-jwt</c> is supported with
        /// the given Key Binding JWT signing algorithm. Checks
        /// <see cref="WellKnownDcSdJwtFormatProperties.KbJwtAlgValues"/>.
        /// </summary>
        public bool SupportsDcSdJwtKbWithAlgorithm(string algorithm)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            IReadOnlyList<string>? algs = formats.GetAlgorithms(
                WellKnownMediaTypes.Jwt.DcSdJwt,
                WellKnownDcSdJwtFormatProperties.KbJwtAlgValues);

            return algs is not null && algs.Contains(algorithm, StringComparer.Ordinal);
        }
    }
}
