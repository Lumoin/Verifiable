using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// Names one wiring member a declared capability needs before a composition can serve it: the
/// wiring group that holds the member and the member itself, for example the
/// <c>BuildJwksDocumentAsync</c> member of the <c>Cryptography</c> group.
/// </summary>
/// <remarks>
/// <para>
/// A composition that declares its capabilities through
/// <see cref="ServerConfiguration.DeclaredCapabilities"/> is validated only for the dependencies of
/// those capabilities. Each dependency found missing is reported as a
/// <see cref="CompositionDependencyFailure"/> carrying this value, so a host reads which member to
/// wire from a typed value instead of parsing an exception message.
/// </para>
/// <para>
/// The text form is the member path the host writes in code: <c>Group.Member</c>, or the member
/// alone when <see cref="Group"/> is empty because the member sits on the integration itself.
/// Ordering and equality compare the group and member ordinally.
/// </para>
/// </remarks>
/// <param name="Group">
/// The wiring group holding the member, such as <c>Cryptography</c> or <c>Codecs</c>; empty when the
/// member is declared on the integration itself.
/// </param>
/// <param name="Member">The member name within its group; never blank.</param>
[DebuggerDisplay("{ToString(),nq}")]
public readonly record struct CompositionDependency(string Group, string Member)
{
    /// <summary>
    /// The wiring group holding the member; empty when the member is declared on the integration itself.
    /// </summary>
    /// <exception cref="ArgumentNullException">The group is <see langword="null"/>.</exception>
    public string Group { get; } = Group ?? throw new ArgumentNullException(nameof(Group));


    /// <summary>The member name within its group.</summary>
    /// <exception cref="ArgumentException">The member is <see langword="null"/>, empty or whitespace.</exception>
    public string Member { get; } = !string.IsNullOrWhiteSpace(Member)
        ? Member
        : throw new ArgumentException("A composition dependency names a member.", nameof(Member));


    /// <summary>
    /// Returns the member path: <c>Group.Member</c>, or the member alone when the group is empty.
    /// </summary>
    /// <returns>The member path a host writes to wire the dependency.</returns>
    public override string ToString()
    {
        string member = Member ?? string.Empty;

        return string.IsNullOrEmpty(Group) ? member : $"{Group}.{member}";
    }
}
