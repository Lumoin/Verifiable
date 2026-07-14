using System;
using System.Buffers;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> writer for a <see cref="RelatedOriginsDocument"/>, producing the wire
/// bytes a relying party hosts at <see cref="WellKnownWebAuthnValues.RelatedOriginsWellKnownPath"/> under
/// the <c>application/json</c> content type
/// (<see cref="Verifiable.JCose.WellKnownMediaTypes.Application.Json"/>), per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">W3C Web Authentication Level 3,
/// section 5.11</see>. Lives beside <see cref="RelatedOriginsJsonReader"/> for the same reason
/// <see cref="ClientDataJsonReader"/> lives here rather than in <c>Verifiable.Fido2</c>: the FIDO2 library
/// stays serialization-agnostic.
/// </summary>
/// <remarks>
/// Refuses to emit a document the client-run related origins validation procedure
/// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-validating-relation-origin">section 5.11.1</see>)
/// would reject: an empty <see cref="RelatedOriginsDocument.Origins"/> (section 5.11's "one or more
/// strings") and an entry that <see cref="RelatedOrigins.IsValidOrigin"/> rejects both throw
/// <see cref="ArgumentException"/> naming <paramref name="document"/> at the parameter named
/// <c>document</c> — a single exception type for both violations, since both describe a caller-supplied
/// <see cref="RelatedOriginsDocument"/> value that this writer refuses to serialize, as distinct from
/// <see cref="Fido2FormatException"/>, which this codebase reserves for malformed WIRE input on the read
/// side (see its own summary). The secure default is to never round-trip an origin string the reader — or
/// the client's own validation procedure — would refuse.
/// </remarks>
public static class RelatedOriginsJsonWriter
{
    /// <summary>The <c>origins</c> member name.</summary>
    private const string OriginsMember = "origins";


    /// <summary>
    /// Writes <paramref name="document"/> as UTF-8 JSON to <paramref name="destination"/>.
    /// </summary>
    /// <param name="document">The document to write.</param>
    /// <param name="destination">The buffer the UTF-8 JSON bytes are written to.</param>
    /// <exception cref="ArgumentNullException"><paramref name="document"/> or <paramref name="destination"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="document"/>'s <see cref="RelatedOriginsDocument.Origins"/> is empty, or one of its
    /// entries is not a structurally valid HTTPS origin per <see cref="RelatedOrigins.IsValidOrigin"/>.
    /// </exception>
    public static void Write(RelatedOriginsDocument document, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(destination);

        if(document.Origins.Count == 0)
        {
            throw new ArgumentException("The related-origins document MUST carry one or more origins.", nameof(document));
        }

        foreach(string origin in document.Origins)
        {
            if(!RelatedOrigins.IsValidOrigin(origin))
            {
                throw new ArgumentException($"The origin '{origin}' is not a structurally valid HTTPS origin.", nameof(document));
            }
        }

        using Utf8JsonWriter writer = new(destination);
        writer.WriteStartObject();
        writer.WriteStartArray(OriginsMember);
        foreach(string origin in document.Origins)
        {
            writer.WriteStringValue(origin);
        }
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();
    }
}
