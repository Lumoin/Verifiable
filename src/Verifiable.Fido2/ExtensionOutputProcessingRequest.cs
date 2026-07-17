using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The inputs to one extension's <see cref="ExtensionOutputProcessDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level 3,
/// section 9: WebAuthn Extensions</see>. Mirrors <see cref="AttestationVerificationRequest"/>'s
/// shape: a single sealed class carrying every input a processing delegate needs, so one delegate
/// signature serves every registered extension.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This request only references caller-owned buffers; it does not take
/// ownership of <see cref="ClientOutputJson"/> or <see cref="AuthenticatorOutputCbor"/>, and does
/// not dispose them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ExtensionOutputProcessingRequest
{
    /// <summary>
    /// Initializes an <see cref="ExtensionOutputProcessingRequest"/> for one extension identifier.
    /// </summary>
    /// <param name="identifier">The extension identifier, per <see cref="Identifier"/>.</param>
    /// <param name="clientOutputJson">The client extension output slice, per <see cref="ClientOutputJson"/>.</param>
    /// <param name="authenticatorOutputCbor">The authenticator extension output slice, per <see cref="AuthenticatorOutputCbor"/>.</param>
    /// <param name="pool">The memory pool, per <see cref="Pool"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="identifier"/> is <see langword="null"/> or empty.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public ExtensionOutputProcessingRequest(
        string identifier,
        ReadOnlyMemory<byte>? clientOutputJson,
        ReadOnlyMemory<byte>? authenticatorOutputCbor,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        ArgumentNullException.ThrowIfNull(pool);

        Identifier = identifier;
        ClientOutputJson = clientOutputJson;
        AuthenticatorOutputCbor = authenticatorOutputCbor;
        Pool = pool;
    }


    /// <summary>
    /// The extension identifier this request carries outputs for, matched case-sensitively by
    /// <see cref="Fido2ExtensionSelectors.FromIdentifiers"/>.
    /// </summary>
    public string Identifier { get; }

    /// <summary>
    /// The client extension output's raw, still-encoded JSON value slice from
    /// <c>clientExtensionResults</c>, or <see langword="null"/> when this extension produced no
    /// client extension output.
    /// </summary>
    public ReadOnlyMemory<byte>? ClientOutputJson { get; }

    /// <summary>
    /// The authenticator extension output's raw, still-encoded CBOR value slice from <c>authData</c>'s
    /// <c>extensions</c> map, or <see langword="null"/> when this extension produced no
    /// authenticator extension output.
    /// </summary>
    public ReadOnlyMemory<byte>? AuthenticatorOutputCbor { get; }

    /// <summary>
    /// The memory pool a processing delegate rents working buffers from, for example when decoding
    /// <see cref="AuthenticatorOutputCbor"/> or performing key-agreement computations the
    /// extension's own semantics require.
    /// </summary>
    public MemoryPool<byte> Pool { get; }


    /// <summary>
    /// A debugger-friendly summary of the extension identifier and which sides produced an
    /// output, rather than every field, matching this codebase's convention for non-owning input
    /// bags.
    /// </summary>
    private string DebuggerDisplay =>
        $"ExtensionOutputProcessingRequest(Identifier={Identifier}, ClientOutputJson={(ClientOutputJson is null ? "absent" : $"{ClientOutputJson.Value.Length} bytes")}, AuthenticatorOutputCbor={(AuthenticatorOutputCbor is null ? "absent" : $"{AuthenticatorOutputCbor.Value.Length} bytes")})";
}
