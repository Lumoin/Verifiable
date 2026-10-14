using Verifiable.Cryptography;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The DPoP proof validation the library's servers run when the application assigns no
/// <see cref="AuthorizationServerIntegration.ValidateDpopProofAsync"/>: <see cref="DpopProofValidator"/>'s overload
/// without a <see cref="VerificationDelegate"/>, so the provider the cryptographic function registry serves for the
/// family of the proof's public key verifies its signature, reading the proof with the server's
/// <see cref="AuthorizationServerCodecs.DpopProofParser"/>.
/// </summary>
/// <remarks>
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate a DPoP
/// proof, the receiving server MUST ensure the following", among them check 6, "The JWT signature verifies with the
/// public key contained in the jwk JOSE Header Parameter." The server's wiring supplies what that overload takes: the
/// codecs' <see cref="AuthorizationServerCodecs.DpopProofParser"/>, <see cref="AuthorizationServerCodecs.Encoder"/> and
/// <see cref="AuthorizationServerCodecs.Decoder"/>, the server's clock and the integration's pool, with
/// <see cref="WellKnownDpopValues.DefaultIatSkew"/> as the <c>iat</c> window. An application that binds its own
/// verification primitive, or wants another window, assigns
/// <see cref="AuthorizationServerIntegration.ValidateDpopProofAsync"/> instead. A composition whose codecs carry the
/// parser, encoder and decoder validates proofs this way, so <see cref="AuthorizationServerIntegration.Validate()"/>
/// requires its nonce and HMAC delegates; the cryptographic function registry is the application's startup to
/// initialize and is checked when a proof is validated, an uninitialized registry throwing before any check runs.
/// </remarks>
public static class DefaultDpopProofValidation
{
    /// <summary>
    /// Validates <paramref name="request"/>'s proof through the registry form of
    /// <see cref="DpopProofValidator"/> with the server's codecs, clock and pool.
    /// </summary>
    /// <param name="request">The proof and what the receiver expects of it.</param>
    /// <param name="codecs">The server's codecs: the proof parser, the base64url encoder and the decoder are read.</param>
    /// <param name="timeProvider">The server's clock the <c>iat</c> window is checked against.</param>
    /// <param name="memoryPool">The integration's pool decoded octets and the reconstructed public key are rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validated claims and thumbprint, or the reason the proof is refused.</returns>
    /// <exception cref="ArgumentNullException">Thrown when an argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="codecs"/> has no <see cref="AuthorizationServerCodecs.DpopProofParser"/>,
    /// <see cref="AuthorizationServerCodecs.Encoder"/> or <see cref="AuthorizationServerCodecs.Decoder"/> wired, or the
    /// cryptographic function registry has not been initialized: the application's composition, never the presented
    /// proof.
    /// </exception>
    public static ValueTask<DpopProofValidationResult> ValidateAsync(
        DpopProofValidationRequest request,
        AuthorizationServerCodecs codecs,
        TimeProvider timeProvider,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(codecs);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);

        DpopJwsPartParser parser = codecs.DpopProofParser
            ?? throw new InvalidOperationException("The default DPoP proof validation requires AuthorizationServerCodecs.DpopProofParser.");
        EncodeDelegate encoder = codecs.Encoder
            ?? throw new InvalidOperationException("The default DPoP proof validation requires AuthorizationServerCodecs.Encoder.");
        DecodeDelegate decoder = codecs.Decoder
            ?? throw new InvalidOperationException("The default DPoP proof validation requires AuthorizationServerCodecs.Decoder.");

        return DpopProofValidator.ValidateAsync(
            request, parser, encoder, decoder, timeProvider, memoryPool, WellKnownDpopValues.DefaultIatSkew, cancellationToken);
    }
}
