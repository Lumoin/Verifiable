using System.Formats.Cbor;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default CBOR reader for the authenticator data <c>extensions</c> map — the
/// authenticator-side counterpart to the <c>ClientExtensionOutputsJsonReader</c> JSON reader.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-extension-processing">W3C Web
/// Authentication Level 3, section 9.5: Authenticator Extension Processing</see>: "the extensions part
/// of the authenticator data is a CBOR map where each key is an extension identifier and the
/// corresponding value is the authenticator extension output for that extension." This reader
/// captures each member's raw, still-encoded value slice (via
/// <see cref="CborReader.ReadEncodedValue"/>) rather than interpreting it — a registered
/// <see cref="ExtensionOutputProcessDelegate"/> decodes the value for the one extension identifier it
/// understands, mirroring how the client-side reader defers value interpretation.
/// </para>
/// <para>
/// Reads with <see cref="CborConformanceMode.Ctap2Canonical"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>, which already rejects a repeated top-level extension identifier (it has
/// no single unambiguous value) or a non-map top level at the framework level; this reader
/// additionally rejects any content trailing the map's end. Every produced
/// <see cref="Fido2ExtensionOutput.Value"/> aliases the buffer passed to <see cref="Read"/> (wrap,
/// don't copy).
/// </para>
/// </remarks>
public static class AuthenticatorExtensionOutputsCborReader
{
    /// <summary>
    /// Parses the authenticator data <c>extensions</c> CBOR bytes into one
    /// <see cref="Fido2ExtensionOutput"/> per top-level member, in wire order. Values are not
    /// interpreted.
    /// </summary>
    /// <param name="authenticatorExtensionOutputs">The raw authenticator data <c>extensions</c> bytes.</param>
    /// <returns>The decoded authenticator extension outputs, one per top-level member.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="authenticatorExtensionOutputs"/> is not a CTAP2 canonical CBOR map (including a
    /// repeated extension identifier), or content trails the map.
    /// </exception>
    public static IReadOnlyList<Fido2ExtensionOutput> Read(ReadOnlyMemory<byte> authenticatorExtensionOutputs)
    {
        try
        {
            var reader = new CborReader(authenticatorExtensionOutputs, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            var outputs = new List<Fido2ExtensionOutput>();

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string identifier = reader.ReadTextString();
                entriesRead++;

                ReadOnlyMemory<byte> value = reader.ReadEncodedValue();
                outputs.Add(new Fido2ExtensionOutput(identifier, value));
            }

            reader.ReadEndMap();

            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException($"The authenticator data extensions buffer carries {reader.BytesRemaining} trailing byte(s) beyond its single CBOR map.");
            }

            return outputs;
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException or FormatException)
        {
            throw new Fido2FormatException("The authenticator data extensions bytes are not valid CTAP2 canonical CBOR conforming to WebAuthn L3 section 9.5.", exception);
        }
    }
}
