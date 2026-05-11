using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// The identifier of a DCQL Credential Query — the <c>id</c> field of an entry
/// in the DCQL query's <c>credentials</c> list per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#dcql">OID4VP 1.0 §7</see>.
/// </summary>
/// <remarks>
/// The same identifier keys the matched presentation array in the
/// <c>vp_token</c> response per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#response-parameters">OID4VP 1.0 §8.1</see>.
/// The Verifier sets this when constructing the JAR's DCQL query and threads
/// it through the flow so the response handler can locate the correct
/// presentation in the JSON wire payload by name.
/// </remarks>
/// <param name="Value">The opaque identifier string.</param>
[DebuggerDisplay("Value={Value}")]
public sealed record CredentialQueryId(string Value);
