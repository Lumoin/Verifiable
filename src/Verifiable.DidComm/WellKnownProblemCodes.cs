namespace Verifiable.DidComm;

/// <summary>
/// The descriptor tokens defined by the DIDComm spec for problem codes, and the one full code the spec
/// names directly, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#descriptors">DIDComm Messaging v2.1 §Descriptors</see>
/// and §Cascading Problems.
/// </summary>
/// <remarks>
/// These are reuse constants for building and prefix-matching problem codes — the descriptor set is open,
/// so individual protocols define more granular descriptors (DIDComm v2.1 §Descriptors), and these are not
/// exhaustive. A descriptor may be used by itself or as a prefix to a more specific one; the values here
/// are the descriptor tokens (and dotted sub-descriptor paths), not whole codes, except
/// <see cref="MaxErrorsExceeded"/>, which is the complete abort code the spec mandates for the
/// max-error-count circuit breaker.
/// </remarks>
public static class WellKnownProblemCodes
{
    /// <summary>The <c>trust</c> descriptor — failed to achieve required trust (DIDComm v2.1 §Descriptors).</summary>
    public static string Trust => "trust";

    /// <summary>The <c>trust.crypto</c> descriptor — a cryptographic operation failed (DIDComm v2.1 §Descriptors).</summary>
    public static string TrustCrypto => "trust.crypto";

    /// <summary>The <c>xfer</c> descriptor — unable to transport data (DIDComm v2.1 §Descriptors).</summary>
    public static string Transfer => "xfer";

    /// <summary>The <c>did</c> descriptor — a DID is unusable (DIDComm v2.1 §Descriptors).</summary>
    public static string Did => "did";

    /// <summary>The <c>msg</c> descriptor — a bad message as seen by an application-level protocol (DIDComm v2.1 §Descriptors).</summary>
    public static string Message => "msg";

    /// <summary>The <c>me</c> descriptor — an internal error in the sender's system (DIDComm v2.1 §Descriptors).</summary>
    public static string Me => "me";

    /// <summary>The <c>me.res</c> descriptor — a required resource is inadequate or unavailable (DIDComm v2.1 §Descriptors).</summary>
    public static string MeResource => "me.res";

    /// <summary>The <c>me.res.net</c> sub-descriptor — a network resource is inadequate or unavailable (DIDComm v2.1 §Descriptors).</summary>
    public static string MeResourceNetwork => "me.res.net";

    /// <summary>The <c>me.res.memory</c> sub-descriptor (DIDComm v2.1 §Descriptors).</summary>
    public static string MeResourceMemory => "me.res.memory";

    /// <summary>The <c>me.res.storage</c> sub-descriptor (DIDComm v2.1 §Descriptors).</summary>
    public static string MeResourceStorage => "me.res.storage";

    /// <summary>The <c>me.res.compute</c> sub-descriptor (DIDComm v2.1 §Descriptors).</summary>
    public static string MeResourceCompute => "me.res.compute";

    /// <summary>The <c>me.res.money</c> sub-descriptor (DIDComm v2.1 §Descriptors).</summary>
    public static string MeResourceMoney => "me.res.money";

    /// <summary>The <c>req</c> descriptor — circumstances don't satisfy requirements (DIDComm v2.1 §Descriptors).</summary>
    public static string Requirement => "req";

    /// <summary>The <c>req.time</c> descriptor — failed to satisfy timing constraints (DIDComm v2.1 §Descriptors).</summary>
    public static string RequirementTime => "req.time";

    /// <summary>The <c>legal</c> descriptor — failed for legal reasons (DIDComm v2.1 §Descriptors).</summary>
    public static string Legal => "legal";

    /// <summary>
    /// The complete abort code <c>e.p.req.max-errors-exceeded</c> an implementation sends to abort a
    /// protocol once its max-error-count circuit breaker trips (DIDComm v2.1 §Cascading Problems).
    /// </summary>
    public static string MaxErrorsExceeded => "e.p.req.max-errors-exceeded";
}
