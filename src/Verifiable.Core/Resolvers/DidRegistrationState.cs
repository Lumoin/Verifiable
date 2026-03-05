using System;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// The state of a DID registration operation as defined by the
/// <see href="https://identity.foundation/did-registration/#didstate">DIF DID Registration specification</see>.
/// </summary>
public enum DidRegistrationStatus
{
    /// <summary>
    /// The operation completed successfully. The DID and DID document are available.
    /// </summary>
    Finished,

    /// <summary>
    /// The operation failed. The error description is available.
    /// </summary>
    Failed,

    /// <summary>
    /// The registrar requires the client to perform an action before the operation
    /// can continue (e.g., sign a payload in client-managed secret mode, fund a
    /// blockchain transaction, confirm a governance approval).
    /// </summary>
    Action,

    /// <summary>
    /// The registrar is processing asynchronously. The client should poll using
    /// the <see cref="DidRegistrationState.JobId"/>.
    /// </summary>
    Wait
}

/// <summary>
/// The state of a DID registration operation, including the status, the DID (if known),
/// and any action instructions or error information.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://identity.foundation/did-registration/#didstate">DIF DID Registration section didState</see>.
/// </para>
/// </remarks>
public sealed class DidRegistrationState
{
    /// <summary>
    /// The current status of the registration operation.
    /// </summary>
    public required DidRegistrationStatus Status { get; init; }

    /// <summary>
    /// The DID that is the subject of this operation, or <see langword="null"/> if not yet known
    /// (e.g., during a <c>create</c> before the DID is assigned).
    /// </summary>
    public string? Did { get; init; }

    /// <summary>
    /// A stable job identifier for polling when <see cref="Status"/> is <see cref="DidRegistrationStatus.Wait"/>.
    /// </summary>
    public string? JobId { get; init; }

    /// <summary>
    /// The error string when <see cref="Status"/> is <see cref="DidRegistrationStatus.Failed"/>.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// A human-readable description of the action the client must perform when
    /// <see cref="Status"/> is <see cref="DidRegistrationStatus.Action"/>.
    /// </summary>
    public string? ActionDescription { get; init; }

    /// <summary>
    /// The signing request for client-managed secret mode. The client must sign the
    /// payload and return the signature as the next input.
    /// </summary>
    public SigningRequest? SigningRequest { get; init; }
}

/// <summary>
/// A signing request issued by the registrar in client-managed secret mode.
/// The client signs the payload and returns a <see cref="SigningResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://identity.foundation/did-registration/#client-managed-secret-mode">DIF DID Registration client-managed secret mode</see>.
/// </para>
/// </remarks>
public sealed class SigningRequest
{
    /// <summary>
    /// An identifier for this signing request, used to correlate with the response.
    /// </summary>
    public required string RequestId { get; init; }

    /// <summary>
    /// The payload to sign.
    /// </summary>
    public required ReadOnlyMemory<byte> Payload { get; init; }

    /// <summary>
    /// The key identifier that should be used for signing.
    /// </summary>
    public string? Kid { get; init; }

    /// <summary>
    /// The algorithm to use for signing (e.g., <c>"EdDSA"</c>, <c>"ES256"</c>).
    /// </summary>
    public string? Algorithm { get; init; }
}

/// <summary>
/// A signing response from the client in client-managed secret mode.
/// </summary>
public sealed class SigningResponse
{
    /// <summary>
    /// The identifier of the signing request this responds to.
    /// </summary>
    public required string RequestId { get; init; }

    /// <summary>
    /// The signature produced by the client.
    /// </summary>
    public required ReadOnlyMemory<byte> Signature { get; init; }

    /// <summary>
    /// The key identifier used for signing.
    /// </summary>
    public string? Kid { get; init; }

    /// <summary>
    /// The algorithm used for signing.
    /// </summary>
    public string? Algorithm { get; init; }
}
