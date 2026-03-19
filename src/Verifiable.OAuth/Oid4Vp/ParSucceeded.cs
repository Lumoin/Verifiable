using System;
using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.OAuth;
using Verifiable.OAuth.Par;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Carries a successful PAR HTTP response. Transitions from <see cref="ParRequestReady"/>
/// to <see cref="ParCompleted"/>. This input arrives at the first DB persistence point.
/// </summary>
/// <param name="Par">The PAR response body parsed from the authorization server.</param>
/// <param name="Nonce">The freshly generated transaction nonce for this flow.</param>
/// <param name="Query">The prepared DCQL query to embed in the JAR.</param>
/// <param name="EncryptionKeyPair">
/// The freshly generated ephemeral ECDH key pair for direct_post.jwt response encryption.
/// Ownership transfers to the resulting <see cref="ParCompleted"/> state.
/// </param>
/// <param name="ReceivedAt">The UTC instant the PAR response was received.</param>
[DebuggerDisplay("ParSucceeded RequestUri={Par.RequestUri}")]
public sealed record ParSucceeded(
    ParResponse Par,
    TransactionNonce Nonce,
    PreparedDcqlQuery Query,
    EphemeralEncryptionKeyPair EncryptionKeyPair,
    DateTimeOffset ReceivedAt): OAuthFlowInput;
