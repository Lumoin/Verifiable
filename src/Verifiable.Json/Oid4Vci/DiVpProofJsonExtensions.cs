using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.OAuth.Oid4Vci;

namespace Verifiable.Json;

/// <summary>
/// Builds the default <c>System.Text.Json</c> implementation of
/// <see cref="DeserializeDiVpPresentationDelegate"/> — the JSON-side seam the
/// <c>Verifiable.OAuth</c> serialization firewall expects an application to supply when it opts in
/// to library-side verification of OID4VCI 1.0 Appendix F.2 <c>di_vp</c> presentation proofs.
/// </summary>
/// <remarks>
/// The library carries each <c>di_vp</c> array entry verbatim as its serialized JSON in
/// <see cref="CredentialRequest.DiVpProofs"/>; this delegate parses one entry back into the
/// embedded-secured presentation model the W3C Data Integrity verifier consumes. The
/// <see cref="VerifiablePresentationConverter"/> upcasts a presentation carrying a <c>proof</c>
/// member to <see cref="DataIntegritySecuredPresentation"/>, so an entry that carries no Data
/// Integrity proof deserializes to the open base type and yields <see langword="null"/> here —
/// the proof is then rejected as <c>invalid_proof</c>.
/// </remarks>
public static class DiVpProofJsonExtensions
{
    /// <summary>
    /// Creates a <see cref="DeserializeDiVpPresentationDelegate"/> that parses one <c>di_vp</c>
    /// array entry into a <see cref="DataIntegritySecuredPresentation"/> with the supplied
    /// <paramref name="options"/>. Returns <see langword="null"/> when the entry does not parse as a
    /// secured presentation (malformed JSON, or no <c>proof</c> member).
    /// </summary>
    /// <param name="options">The serializer options carrying the Verifiable converters.</param>
    /// <returns>The default di_vp presentation deserialize delegate.</returns>
    public static DeserializeDiVpPresentationDelegate CreateDiVpPresentationDeserializer(
        JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return presentationJson =>
        {
            try
            {
                VerifiablePresentation? presentation =
                    JsonSerializerExtensions.Deserialize<VerifiablePresentation>(presentationJson, options);

                return presentation as DataIntegritySecuredPresentation;
            }
            catch(JsonException)
            {
                return null;
            }
        };
    }
}
