using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Ebsi;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Json.Converters;
using Verifiable.Json.Converters.Dcql;
using Verifiable.Json.StatusList;

namespace Verifiable.Json;

/// <summary>
/// Extension methods that register this library's complete set of <see cref="JsonConverter"/>
/// implementations, and the scalar settings they rely on, on a <see cref="JsonSerializerOptions"/>
/// instance.
/// </summary>
public static class JsonSerializerOptionsVerifiableExtensions
{
    /// <summary>
    /// Builds the <see cref="GenericDidMethod"/> for a decoded DID identifier by dispatching on its
    /// method prefix, so <see cref="ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/> can hand a
    /// concrete factory to the registered <see cref="DidIdConverter"/> without every caller supplying
    /// its own.
    /// </summary>
    private static DidMethodFactoryDelegate DefaultDidIdFactory { get; } = did =>
    {
        return did switch
        {
            var d when d.StartsWith(EbsiDidMethod.Prefix, StringComparison.Ordinal) => new EbsiDidMethod(did),
            var d when d.StartsWith(KeyDidMethod.Prefix, StringComparison.Ordinal) => new KeyDidMethod(did),
            var d when d.StartsWith(WebDidMethod.Prefix, StringComparison.Ordinal) => new WebDidMethod(did),
            _ => new GenericDidMethod(did)
        };
    };


    /// <summary>
    /// Registers every DID document, DID Resolution, Verifiable Credential, DCQL, OID4VP client-metadata,
    /// status list and DIDComm converter this library declares, together with the scalar settings they
    /// rely on: camelCase property names, case-insensitive property matching, null-valued members omitted
    /// on write, and <see cref="VerifiableJsonContext"/> as the source-generated
    /// <see cref="JsonSerializerOptions.TypeInfoResolver"/>.
    /// </summary>
    /// <remarks>
    /// A caller builds its <paramref name="options"/> instance once, with its own <paramref name="pool"/>,
    /// and may call <see cref="JsonSerializerOptions.MakeReadOnly()"/> on the returned instance itself: this
    /// method is the last write the registration needs, since it sets
    /// <see cref="JsonSerializerOptions.TypeInfoResolver"/> rather than leaving it for a later caller to
    /// supply, so freezing right after this call is valid.
    /// </remarks>
    /// <param name="options">The options instance to extend.</param>
    /// <param name="pool">
    /// The memory pool the registered <see cref="Verifiable.Json.StatusList.StatusListJsonConverter"/> and
    /// <see cref="Verifiable.Json.StatusList.StatusListTokenJsonConverter"/> rent their decoded Status List
    /// buffers from. Every caller supplies its own; this method never substitutes a process-wide default.
    /// </param>
    /// <param name="requireDcqlMeta">
    /// Whether a DCQL Credential Query's <c>meta</c> member is required. OpenID for Verifiable
    /// Presentations 1.0 §6.1 requires <c>meta</c> on a Credential Query; <see langword="true"/> (the
    /// default) enforces that requirement, and <see langword="false"/> tolerates query shapes that omit
    /// it, for interoperating with Verifiers that do not send it.
    /// </param>
    /// <returns>The same <paramref name="options"/> instance, so calls chain.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static JsonSerializerOptions ApplyVerifiableDefaults(this JsonSerializerOptions options, BaseMemoryPool pool, bool requireDcqlMeta = true)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(pool);

        options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.PropertyNameCaseInsensitive = true;

        //Source-generated serialization metadata for AOT compatibility.
        options.TypeInfoResolver = VerifiableJsonContext.Default;

        //DID document converters.
        options.Converters.Add(new DidDocumentConverter());
        options.Converters.Add(new DictionaryStringObjectJsonConverter(VerifiableJsonContext.Default));
        options.Converters.Add(new SingleOrArrayControllerConverter());
        options.Converters.Add(new VerificationMethodReferenceConverterFactory());
        options.Converters.Add(new VerificationMethodConverter());
        options.Converters.Add(new ServiceConverter());
        options.Converters.Add(new JsonLdContextConverter());
        options.Converters.Add(new DataIntegrityProofConverter());
        options.Converters.Add(new DidUrlConverter());
        options.Converters.Add(new DidIdConverter(DefaultDidIdFactory));
        options.Converters.Add(new DidDocumentMetadataConverter());

        //JOSE / JWK converter. Guarded by type because ApplyOAuthDefaults registers the same
        //converter for its own OAuth-only composition, and the two methods compose in either order.
        if(!options.Converters.Any(converter => converter is JsonWebKeyJsonConverter))
        {
            options.Converters.Add(new JsonWebKeyJsonConverter());
        }

        //DID Resolution / DID URL Dereferencing result-envelope converters (W3C DID Resolution
        //HTTP(S) binding). The problem-details and metadata converters are registered first so the
        //envelope converters resolve them through GetTypeInfo.
        options.Converters.Add(new DidProblemDetailsConverter());
        options.Converters.Add(new DidResolutionMetadataConverter());
        options.Converters.Add(new DidDereferencingMetadataConverter());
        options.Converters.Add(new DidResolutionResultConverter());
        options.Converters.Add(new DidDereferencingResultConverter());

        //Verifiable Credential converters.
        options.Converters.Add(new IssuerConverter());
        options.Converters.Add(new CredentialSubjectConverter());
        options.Converters.Add(new VerifiableCredentialConverter());
        options.Converters.Add(new VerifiablePresentationConverter());
        options.Converters.Add(new EnvelopedVerifiablePresentationConverter());

        //DCQL converters. CredentialQueryConverter enforces the OID4VP §6.1 'meta'
        //requirement by default; requireDcqlMeta:false tolerates its absence.
        options.Converters.Add(new DcqlQueryConverter());
        options.Converters.Add(new CredentialQueryConverter(requireDcqlMeta));
        options.Converters.Add(new CredentialQueryMetaConverter());
        options.Converters.Add(new ClaimsQueryConverter());
        options.Converters.Add(new TrustedAuthoritiesQueryConverter());
        options.Converters.Add(new CredentialSetQueryConverter());

        //OID4VP client_metadata (Verifier metadata) converters — snake_case wire names
        //and correct shape (bare vp_formats_supported map, jwks as a JSON object).
        options.Converters.Add(new VpFormatsSupportedConverter());
        options.Converters.Add(new VerifierClientMetadataConverter());

        //Status list converters.
        options.Converters.Add(new StatusListJsonConverter(pool));
        options.Converters.Add(new StatusListReferenceJsonConverter());
        options.Converters.Add(new StatusClaimJsonConverter());
        options.Converters.Add(new StatusListAggregationJsonConverter());
        options.Converters.Add(new StatusListTokenJsonConverter(pool));

        //DIDComm plaintext message converter — snake_case wire member names handled manually.
        options.Converters.Add(new DidCommMessageConverter());

        return options;
    }
}
