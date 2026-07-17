using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>largeBlob</c> extension's assertion-side client extension input — one of
/// <see cref="PublicKeyCredentialRequestOptions"/>'s two named extension-input carve-outs (the
/// generic <c>extensions</c> client-input member remains out of scope; see that type's type-level
/// remarks).
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>, client extension input
/// <c>read</c>/<c>write</c> — authentication-only (the registration-side input carries <c>support</c>
/// instead, see <see cref="Fido2LargeBlobRegistrationExtensionInput"/>).
/// </para>
/// <para>
/// <see cref="Read"/> and <see cref="Write"/> are mutually exclusive by construction — only
/// <see cref="ForRead"/> or <see cref="ForWrite"/> can produce an instance, never both members at
/// once — mirroring the CR's own client processing step (":8765-8769" in the local snapshot): "both
/// present" is a client-side <c>NotSupportedError</c>. This structural guarantee (a private
/// constructor plus two named factories) closes that off at the type level rather than needing a
/// runtime check the builder or the JSON writer would otherwise have to repeat.
/// </para>
/// <para>
/// <see cref="Write"/>'s payload and the assertion output's decoded <c>blob</c> are the same domain
/// object — opaque, relying-party-supplied bytes — so both are carried as
/// <see cref="TaggedMemory{T}"/> tagged with the same <see cref="Fido2BufferTags.LargeBlob"/>, not two
/// independently invented carriers.
/// </para>
/// </remarks>
[DebuggerDisplay("Fido2LargeBlobAssertionExtensionInput(Read={Read}, WriteLength={Write?.Length})")]
public sealed record Fido2LargeBlobAssertionExtensionInput
{
    /// <summary>
    /// <see langword="true"/> when the relying party is requesting a large-blob read;
    /// <see langword="null"/> when this input requests a write instead (see <see cref="Write"/>).
    /// </summary>
    public bool? Read { get; private init; }

    /// <summary>
    /// The bytes the relying party wants written to the credential's large-blob storage;
    /// <see langword="null"/> when this input requests a read instead (see <see cref="Read"/>).
    /// </summary>
    public TaggedMemory<byte>? Write { get; private init; }


    /// <summary>
    /// Initializes a new instance. Private: only <see cref="ForRead"/>/<see cref="ForWrite"/>
    /// construct one, which is what keeps <see cref="Read"/>/<see cref="Write"/> mutually exclusive.
    /// </summary>
    private Fido2LargeBlobAssertionExtensionInput()
    {
    }


    /// <summary>
    /// Creates an input requesting a large-blob read.
    /// </summary>
    /// <returns>An input with <see cref="Read"/> set to <see langword="true"/> and <see cref="Write"/> absent.</returns>
    public static Fido2LargeBlobAssertionExtensionInput ForRead() => new() { Read = true };


    /// <summary>
    /// Creates an input requesting a large-blob write.
    /// </summary>
    /// <param name="blob">The bytes to write, tagged with <see cref="Fido2BufferTags.LargeBlob"/>.</param>
    /// <returns>An input with <see cref="Write"/> set to <paramref name="blob"/> and <see cref="Read"/> absent.</returns>
    public static Fido2LargeBlobAssertionExtensionInput ForWrite(TaggedMemory<byte> blob) => new() { Write = blob };
}
