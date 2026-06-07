using System.Buffers;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The request-derived inputs the wallet client passes to the application's
/// <see cref="ProduceVpTokenPresentationsDelegate"/> — everything the
/// application needs to evaluate the query, compute the disclosure decision,
/// and build the presentation, without the client knowing anything
/// format-specific.
/// </summary>
/// <remarks>
/// The wallet client derives this once from the parsed, signature-verified
/// <see cref="AuthorizationRequestObject"/> and the active infrastructure, then
/// hands it to the application's delegate. The application brings its own
/// credentials, keys, and disclosure policy by closure; it runs the wirable
/// Core engine (<c>DcqlEvaluator</c> → <c>DisclosureComputation</c>) and the
/// format primitives behind the delegate.
/// </remarks>
[DebuggerDisplay("Oid4VpPresentationContext ClientId={Request.ClientId}")]
public sealed record Oid4VpPresentationContext
{
    /// <summary>
    /// The parsed, signature-verified Authorization Request. Carries
    /// <c>client_id</c>, <c>response_uri</c>, <c>nonce</c>, <c>transaction_data</c>,
    /// and the <c>dcql_query</c> the application presents against.
    /// </summary>
    public required AuthorizationRequestObject Request { get; init; }

    /// <summary>The prepared DCQL query, ready to feed the disclosure engine.</summary>
    public required PreparedDcqlQuery PreparedQuery { get; init; }

    /// <summary>The current UTC instant, read once from the active TimeProvider.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>Base64url encoder for the application's key-binding, hashing, and wire-encoding steps.</summary>
    public required EncodeDelegate Base64UrlEncoder { get; init; }

    /// <summary>Memory pool for the application's transient cryptographic buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }

    /// <summary>
    /// The threaded per-operation <see cref="ExchangeContext"/> the wallet
    /// client carried into this presentation. Lets the application's
    /// disclosure/credential logic run tenant-scoped — read tenant identity or
    /// per-tenant policy off the context — without capturing it. A lone wallet
    /// receives a fresh empty context and may ignore it.
    /// </summary>
    public required ExchangeContext ExchangeContext { get; init; }
}
