using System.Buffers;
using Verifiable.Fido2;
using Verifiable.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared <c>clientDataJSON</c> authoring for FIDO2/WebAuthn flow and ceremony tests, delegating to
/// the production <see cref="ClientDataJsonWriter"/> so the wire bytes a flow test feeds a verifier
/// are the same bytes a real client would produce.
/// </summary>
/// <remarks>
/// Per the iron oracle rule, flow/ceremony/verifier/CLI/capstone tests call this class: they exercise
/// the production writer (and, downstream, <see cref="ClientDataJsonReader"/>) as part of what they are
/// testing. Reader/edge/format tests — the independent oracle for <see cref="ClientDataJsonReader"/>
/// itself — deliberately keep their own hand-built <c>clientDataJSON</c> strings rather than calling
/// this class, so a defect shared between the writer and this fixture cannot mask a reader defect.
/// </remarks>
internal static class WebAuthnClientDataFixtures
{
    /// <summary>
    /// Writes <paramref name="clientData"/> to its UTF-8 <c>clientDataJSON</c> wire bytes via
    /// <see cref="ClientDataJsonWriter.Write"/>.
    /// </summary>
    /// <param name="clientData">The client data to encode.</param>
    /// <returns>The UTF-8-encoded <c>clientDataJSON</c> bytes.</returns>
    internal static byte[] BuildClientDataJson(ClientData clientData)
    {
        var destination = new ArrayBufferWriter<byte>();
        ClientDataJsonWriter.Write(clientData, destination);

        return destination.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Builds the UTF-8 <c>clientDataJSON</c> wire bytes for a <c>CollectedClientData</c> value with
    /// the given <paramref name="type"/>, <paramref name="challenge"/>, and <paramref name="origin"/>,
    /// and optionally <paramref name="crossOrigin"/>/<paramref name="topOrigin"/>.
    /// </summary>
    /// <param name="type">The client data <c>type</c> member.</param>
    /// <param name="challenge">The base64url-encoded challenge.</param>
    /// <param name="origin">The client-reported origin.</param>
    /// <param name="crossOrigin">The client-reported <c>crossOrigin</c> indicator. Defaults to absent.</param>
    /// <param name="topOrigin">The client-reported <c>topOrigin</c>. Defaults to absent.</param>
    /// <returns>The UTF-8-encoded <c>clientDataJSON</c> bytes.</returns>
    internal static byte[] BuildClientDataJson(string type, string challenge, string origin, bool? crossOrigin = null, string? topOrigin = null)
    {
        return BuildClientDataJson(new ClientData(type, challenge, origin, crossOrigin, topOrigin));
    }


    /// <summary>
    /// Builds the UTF-8 <c>clientDataJSON</c> wire bytes for a <see cref="WellKnownClientDataTypes.Create"/>
    /// registration ceremony with the given <paramref name="challenge"/> and <paramref name="origin"/>.
    /// </summary>
    /// <param name="challenge">The base64url-encoded challenge.</param>
    /// <param name="origin">The client-reported origin.</param>
    /// <returns>The UTF-8-encoded <c>clientDataJSON</c> bytes.</returns>
    internal static byte[] BuildClientDataJson(string challenge, string origin)
    {
        return BuildClientDataJson(WellKnownClientDataTypes.Create, challenge, origin);
    }
}
