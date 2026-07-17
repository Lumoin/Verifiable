using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorLargeBlobs</c> response structure: the <c>get</c> outcome's ONE Required member.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>, the response structure table
/// (lines 7688-7697). This type carries ONLY <c>get</c>'s response; a <c>set</c> outcome (continuation or
/// commit) never produces an instance of this type at all — it is framed as a bare <c>CTAP2_OK</c> with no
/// CBOR body via <c>LargeBlobsResponseReady</c>'s own nullable <c>Response</c>, mirroring
/// <c>CredentialManagementResponseReady</c>/<c>BioEnrollmentResponseReady</c>'s identical nullable-outer-
/// intent shape. Consequently <see cref="Config"/> is REQUIRED here (no default), unlike the multi-shape
/// response records those two commands use.
/// </remarks>
/// <param name="Config">Required (<c>0x01</c>). The requested substring of the stored serialized large-blob array.</param>
[DebuggerDisplay("CtapLargeBlobsResponse(Config.Length={Config.Length})")]
public sealed record CtapLargeBlobsResponse(ReadOnlyMemory<byte> Config);
