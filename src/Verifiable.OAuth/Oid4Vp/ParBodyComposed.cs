using System;
using System.Diagnostics;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Signals that the PAR request body has been composed and is ready to POST.
/// Transitions from <see cref="PkceGenerated"/> to <see cref="ParRequestReady"/>.
/// </summary>
/// <param name="EncodedBody">
/// The serialized PAR request body in <c>application/x-www-form-urlencoded</c> form per
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>.
/// </param>
/// <param name="ComposedAt">The UTC instant at which the body was composed.</param>
[DebuggerDisplay("ParBodyComposed")]
public sealed record ParBodyComposed(
    string EncodedBody,
    DateTimeOffset ComposedAt): OAuthFlowInput;
