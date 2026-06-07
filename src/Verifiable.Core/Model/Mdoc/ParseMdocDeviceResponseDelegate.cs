using System;
using System.Buffers;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Parses the CBOR-encoded ISO/IEC 18013-5 §8.3.2.1 <c>DeviceResponse</c> wire
/// bytes — the base64url-decoded OID4VP <c>vp_token</c> value — into an owned
/// <see cref="MdocParsedDeviceResponse"/> the verifier runs issuer-auth,
/// digest-binding, and device-signed verification against.
/// </summary>
/// <remarks>
/// <para>
/// The verifier-side CBOR seam the OID4VP VP-token flow orchestration composes
/// but does not perform itself (the flow layer cannot decode CBOR). Wired by
/// the application to
/// <c>Verifiable.Cbor.Mdoc.MdocCborDeviceResponseReader.Read</c>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> A successful parse returns an owned
/// <see cref="MdocParsedDeviceResponse"/> the caller disposes; malformed input
/// throws and leaks no pool memory.
/// </para>
/// </remarks>
/// <param name="encodedDeviceResponse">The CBOR-encoded DeviceResponse map bytes.</param>
/// <param name="pool">Memory pool the owned carriers rent from.</param>
/// <returns>The parsed, owned <see cref="MdocParsedDeviceResponse"/>.</returns>
public delegate MdocParsedDeviceResponse ParseMdocDeviceResponseDelegate(
    ReadOnlySpan<byte> encodedDeviceResponse,
    MemoryPool<byte> pool);
