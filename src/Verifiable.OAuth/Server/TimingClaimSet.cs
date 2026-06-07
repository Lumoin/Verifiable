using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The set of JWT timing claims (<c>iat</c>, <c>nbf</c>, <c>exp</c>) a
/// deployment requires on inbound JARs.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7519 §4.1 marks all three as OPTIONAL. FAPI 2.0 §5.2.2 Clause 13
/// mandates <c>exp</c>. The library applies the strictest profile by default
/// (<see cref="All"/>) so the lifetime ceiling check (<c>exp - iat</c>) and
/// not-yet-valid check (<c>nbf</c> after now+skew) are unambiguous.
/// </para>
/// <para>
/// Flag values combine to express any subset; common subsets are exposed as
/// named values (<see cref="ExpOnly"/>, <see cref="All"/>).
/// </para>
/// </remarks>
[Flags]
[DebuggerDisplay("TimingClaimSet={ToString(),nq}")]
public enum TimingClaimSet
{
    /// <summary>No timing claim required.</summary>
    None = 0,

    /// <summary>The <c>iat</c> claim is required.</summary>
    Iat = 1,

    /// <summary>The <c>nbf</c> claim is required.</summary>
    Nbf = 2,

    /// <summary>The <c>exp</c> claim is required.</summary>
    Exp = 4,

    /// <summary>Only <c>exp</c> required (FAPI 2.0 §5.2.2 baseline).</summary>
    ExpOnly = Exp,

    /// <summary>All three timing claims required (library default).</summary>
    All = Iat | Nbf | Exp
}
