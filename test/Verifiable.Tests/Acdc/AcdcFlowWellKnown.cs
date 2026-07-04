namespace Verifiable.Tests.Acdc;

/// <summary>
/// The well-known placeholder and fixture values the ACDC flow minters use. The over-the-wire flow tests exercise
/// the protocol's verifiable bindings — SAIDs, KEL anchoring, the edge chain-of-authority, and registry state — not
/// schema validation or UUID uniqueness, so the values a real Issuer would source from a schema registry or a salt
/// are fixed and named here, keeping the minting readable and the placeholders explicit rather than inline magic
/// strings.
/// </summary>
internal static class AcdcFlowWellKnown
{
    /// <summary>A valid-shape Blake3 SAID placeholder (code <c>E</c> plus filler) substituted for a real SAID during the two-pass mint, then replaced by the computed SAID.</summary>
    public static string SaidPlaceholder { get; } = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// <summary>
    /// A stand-in schema SAID the minted credentials reference. ACDC schema validation is deferred (gated on the
    /// JSON Schema machinery from a related project), so the flow neither resolves nor validates the schema; it uses
    /// a fixed valid-shape SAID rather than a real SAIDified schema.
    /// </summary>
    public static string PlaceholderSchemaSaid { get; } = "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    /// <summary>A stand-in attribute-section SAID for a minimal credential whose attribute section is carried in compact (SAID) form rather than disclosed as a block.</summary>
    public static string PlaceholderAttributeSaid { get; } = "ECCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    /// <summary>An AID that is not the near Issuer, used as the far credential's Issuee to break the <c>I2I</c> chain in the negative edge-chain flow.</summary>
    public static string UnrelatedIssueeAid { get; } = "EZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

    /// <summary>The Issuee AID a graduated credential's attribute block carries; the expanded variant discloses it, the compact variant blinds it behind the attribute section's SAID.</summary>
    public static string GraduatedSubjectAid { get; } = "EHrLi3GjajVgChhB7nQz5JLwzGZ8DhJ9q2Wf6X3y0Tk1";

    /// <summary>The label of the graduated credential's disclosed attribute field; shared so the minter and the verifier agree on it without an inline literal.</summary>
    public static string GraduatedNameLabel { get; } = "name";

    /// <summary>The value of the graduated credential's disclosed attribute field; the expanded variant reveals it, and the SAID binds it so a tampered disclosure no longer compacts to the committed SAID.</summary>
    public static string GraduatedSubjectName { get; } = "Lewis Carroll";

    /// <summary>The Issuee AID an aggregate credential's revealed block carries; the selective disclosure reveals this block while blinding the others, and the AGID still proves the revealed block a member of the committed set.</summary>
    public static string AggregateSubjectAid { get; } = "EJh9LkP2mWcQ7vRtY4nB8sZ6XgF1aD3eK5uH0jC9oVi2";

    /// <summary>The label of an aggregate credential's blinded score block field; the minter writes it into the block whose value the selective disclosure keeps hidden behind the block's SAID.</summary>
    public static string AggregateScoreLabel { get; } = "score";

    /// <summary>The value of an aggregate credential's blinded score block field; the selective disclosure does not reveal it, yet the block's SAID still enters the AGID so its membership is provable.</summary>
    public static string AggregateScoreValue { get; } = "96";

    /// <summary>A fixed salty-nonce for a minted block's or event's UUID (<c>u</c>) field; the flows do not exercise UUID uniqueness, so one nonce serves every block.</summary>
    public static string BlockNonce { get; } = "0ABhY2Rjc3BlY3dvcmtyYXcw";

    /// <summary>The IPEX grant route <c>/ipex/grant</c>: the <c>r</c> field of the exchange message that discloses a credential to a Disclosee.</summary>
    public static string IpexGrantRoute { get; } = "/ipex/grant";

    /// <summary>The IPEX admit route <c>/ipex/admit</c>: the <c>r</c> field of the exchange message a Disclosee returns to accept a grant.</summary>
    public static string IpexAdmitRoute { get; } = "/ipex/admit";

    /// <summary>The Disclosee's AID, the sender of the admit exchange message; the flow exercises the routed exchange and the proofs it carries, not the exchange-envelope signature, so the Disclosee's AID is a fixed value.</summary>
    public static string DiscloseeAid { get; } = "EKqL8oF3wY7nT2mV5bH9jR4dG6sP1aC0eU8xN3iZ7kW2";

    /// <summary>The ACDC JSON version string with a zeroed size, restamped to the serialized byte count when an event is minted.</summary>
    public static string AcdcProbeVersion { get; } = "ACDCCAACAAJSONAAAA.";

    /// <summary>The KERI JSON version string with a zeroed size, used to measure a serialization before its size is stamped.</summary>
    public static string KeriProbeVersion { get; } = "KERI10JSON000000_";
}
