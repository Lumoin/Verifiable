using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// The versioning and bounding constants <see cref="CtapAuthenticatorSnapshotCborWriter"/> and
/// <see cref="CtapAuthenticatorSnapshotCborReader"/> share.
/// </summary>
/// <remarks>
/// Contract R-5: a leading format-version integer, checked by the reader before any other field is
/// parsed; an unrecognized version fails closed rather than attempting a best-effort parse. Every other
/// bound here defends the reader against a truncated or adversarially crafted snapshot claiming an
/// unreasonable length/count — generous enough for any legitimate authenticator state this simulator can
/// reach (<see cref="CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity"/> alone is 4096), never
/// so tight it could reject a real one.
/// </remarks>
public static class CtapAuthenticatorSnapshotFormat
{
    /// <summary>
    /// The only snapshot format version <see cref="CtapAuthenticatorSnapshotCborReader"/> accepts. A
    /// future incompatible layout change bumps this value; the reader fails closed on any other value it
    /// encounters.
    /// </summary>
    public const ulong CurrentVersion = 1;

    /// <summary>The maximum legal byte length for any single length-prefixed byte string field.</summary>
    public const int MaxByteStringLength = 1_048_576;

    /// <summary>The maximum legal UTF-8 byte length for any single length-prefixed text string field.</summary>
    public const int MaxTextStringLength = 65_536;

    /// <summary>The maximum legal item count for any array field (credentials, bio templates, RP ID lists).</summary>
    public const int MaxArrayCount = 100_000;
}
