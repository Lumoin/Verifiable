using System;
using System.Buffers.Binary;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// One <c>Name</c> term of a command's handle-Name area (TPM 2.0 Library Part 1, clause 15.7 equation 15's
/// <c>Name1..N</c>), in whichever of the two forms the addressed entity has: a computed
/// <c>TPM2B_NAME</c> for an object, an NV Index or any other entity whose Name is
/// <c>nameAlg ‖ H(public area)</c>, or the entity's own 4-octet big-endian handle value for a permanent
/// entity, whose Name IS its handle (Part 1, clause 13, Table 9).
/// </summary>
/// <remarks>
/// A term never owns anything: the computed form holds a BORROWED reference to a <see cref="Tpm2bName"/>
/// carrier owned by durable state or by the command request being verified, and the handle form holds a value
/// that is materialized into pooled scratch by the effect that digests the area. Absent terms are the
/// <see langword="default"/> value, which contributes nothing.
/// </remarks>
public readonly record struct TpmHandleName
{
    /// <summary>
    /// The borrowed computed Name, or <see langword="null"/> for an absent or handle-form term.
    /// </summary>
    private Tpm2bName? BorrowedName { get; }

    /// <summary>
    /// The permanent entity's handle value, meaningful only when <see cref="IsHandleForm"/> is set.
    /// </summary>
    private uint HandleValue { get; }

    /// <summary>
    /// Whether the term is a permanent entity's 4-octet handle rather than a computed Name.
    /// </summary>
    private bool IsHandleForm { get; }

    /// <summary>
    /// Initializes a term in one of its two forms, or the absent term.
    /// </summary>
    /// <param name="borrowedName">The borrowed computed Name, or <see langword="null"/>.</param>
    /// <param name="handleValue">The permanent entity's handle value.</param>
    /// <param name="isHandleForm">Whether the term is the handle form.</param>
    private TpmHandleName(Tpm2bName? borrowedName, uint handleValue, bool isHandleForm)
    {
        BorrowedName = borrowedName;
        HandleValue = handleValue;
        IsHandleForm = isHandleForm;
    }

    /// <summary>
    /// Gets the absent term, contributing no octets — the shape of a command that addresses fewer than three
    /// handles.
    /// </summary>
    public static TpmHandleName None => default;

    /// <summary>
    /// Gets the Empty-Buffer term: PRESENT in the area but contributing no octets — the Name of a sequence
    /// object ("If an authorization or audit for a sequence object requires computation of a cpHash and an
    /// rpHash, the Name associated with sequenceHandle will be the Empty Buffer", TPM 2.0 Library Part 1,
    /// clause 29.4.6; clause 13, Table 9, footnote (1); Part 3, clause 17.7.1), which Part 4's
    /// <c>EntityGetName</c> answers as a zero-size Name for the <c>nameAlg == TPM_ALG_NULL</c> object a
    /// sequence context is.
    /// </summary>
    public static TpmHandleName EmptyBuffer => FromName(Tpm2bName.Empty);

    /// <summary>
    /// Creates a term borrowing an entity's computed Name.
    /// </summary>
    /// <param name="name">The Name carrier; borrowed, never disposed through this term, and required to outlive the effect that digests the area.</param>
    /// <returns>The Name term.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="name"/> is <see langword="null"/>.</exception>
    public static TpmHandleName FromName(Tpm2bName name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return new TpmHandleName(name, handleValue: 0, isHandleForm: false);
    }

    /// <summary>
    /// Creates a term for a permanent entity, whose Name is its own 4-octet big-endian handle value (TPM 2.0
    /// Library Part 1, clause 13, Table 9).
    /// </summary>
    /// <param name="handle">The entity's handle.</param>
    /// <returns>The handle-form Name term.</returns>
    public static TpmHandleName FromHandle(uint handle) => new(borrowedName: null, handleValue: handle, isHandleForm: true);

    /// <summary>
    /// Gets whether the term contributes octets to the handle-Name area.
    /// </summary>
    public bool IsPresent => IsHandleForm || BorrowedName is not null;

    /// <summary>
    /// Gets the number of octets the term contributes.
    /// </summary>
    public int Length => IsHandleForm ? sizeof(uint) : BorrowedName?.Size ?? 0;

    /// <summary>
    /// Writes the term's octets to the start of the destination.
    /// </summary>
    /// <param name="destination">The scratch the handle-Name area is being laid out in; must hold at least <see cref="Length"/> octets.</param>
    public void CopyTo(Span<byte> destination)
    {
        if(IsHandleForm)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination, HandleValue);

            return;
        }

        BorrowedName?.Span.CopyTo(destination);
    }

    /// <summary>
    /// Reads the term's octets contiguously, for a consumer that needs one span rather than a layout — the
    /// handle form is materialized into the supplied scratch, the computed form is read straight out of the
    /// carrier that owns it, and an absent term reads empty.
    /// </summary>
    /// <param name="handleScratch">Scratch of at least <see langword="sizeof"/>(<see cref="uint"/>) octets, used only by the handle form.</param>
    /// <returns>The term's octets.</returns>
    public ReadOnlySpan<byte> Read(Span<byte> handleScratch)
    {
        if(IsHandleForm)
        {
            BinaryPrimitives.WriteUInt32BigEndian(handleScratch, HandleValue);

            return handleScratch[..sizeof(uint)];
        }

        return BorrowedName is null ? ReadOnlySpan<byte>.Empty : BorrowedName.Span;
    }
}

/// <summary>
/// A command's whole handle-Name area — the ordered <c>Name1 ‖ Name2 ‖ Name3</c> term list cpHash covers
/// between the command code and the parameters (TPM 2.0 Library Part 1, clause 15.7 equation 15, printed page
/// 103). That same equation — <c>cpHash = HsessionAlg(commandCode {Name1 {Name2 {Name3}}} {parameters})</c> —
/// caps the term list at three, so the area is exactly three ordered <see cref="TpmHandleName"/> slots,
/// trailing ones absent.
/// </summary>
/// <remarks>
/// The area is held as its terms rather than as concatenated octets because a pure transition holds no memory
/// pool: the terms are borrows and handle values, and the effect that digests them lays them out in pooled
/// scratch of its own frame — the same split <c>FoldedSessionNonces</c> makes for equation 17's nonce terms.
/// </remarks>
public readonly record struct TpmCommandHandleNames
{
    /// <summary>
    /// Initializes an area from its three ordered terms.
    /// </summary>
    /// <param name="first">The first Name term.</param>
    /// <param name="second">The second Name term.</param>
    /// <param name="third">The third Name term.</param>
    private TpmCommandHandleNames(TpmHandleName first, TpmHandleName second, TpmHandleName third)
    {
        First = first;
        Second = second;
        Third = third;
    }

    /// <summary>
    /// Gets the empty area — the shape of a command that addresses no handles at all, such as
    /// <c>TPM2_GetRandom()</c>.
    /// </summary>
    public static TpmCommandHandleNames None => default;

    /// <summary>
    /// Gets the first Name term.
    /// </summary>
    public TpmHandleName First { get; }

    /// <summary>
    /// Gets the second Name term, absent for a single-handle command.
    /// </summary>
    public TpmHandleName Second { get; }

    /// <summary>
    /// Gets the third Name term, absent for every command but <c>TPM2_NV_Certify()</c>.
    /// </summary>
    public TpmHandleName Third { get; }

    /// <summary>
    /// Creates a single-handle command's area.
    /// </summary>
    /// <param name="first">The sole Name term.</param>
    /// <returns>The handle-Name area.</returns>
    public static TpmCommandHandleNames Of(TpmHandleName first) => new(first, TpmHandleName.None, TpmHandleName.None);

    /// <summary>
    /// Creates a two-handle command's area.
    /// </summary>
    /// <param name="first">The first Name term, in the command's own handle order.</param>
    /// <param name="second">The second Name term.</param>
    /// <returns>The handle-Name area.</returns>
    public static TpmCommandHandleNames Of(TpmHandleName first, TpmHandleName second) => new(first, second, TpmHandleName.None);

    /// <summary>
    /// Creates a three-handle command's area.
    /// </summary>
    /// <param name="first">The first Name term, in the command's own handle order.</param>
    /// <param name="second">The second Name term.</param>
    /// <param name="third">The third Name term.</param>
    /// <returns>The handle-Name area.</returns>
    public static TpmCommandHandleNames Of(TpmHandleName first, TpmHandleName second, TpmHandleName third) => new(first, second, third);

    /// <summary>
    /// Gets the total number of octets the area contributes to cpHash.
    /// </summary>
    public int Length => First.Length + Second.Length + Third.Length;

    /// <summary>
    /// Lays the terms out contiguously, in order, at the start of the destination.
    /// </summary>
    /// <param name="destination">The pooled scratch cpHash is being assembled in; must hold at least <see cref="Length"/> octets.</param>
    public void CopyTo(Span<byte> destination)
    {
        int offset = 0;
        First.CopyTo(destination);
        offset += First.Length;
        Second.CopyTo(destination[offset..]);
        offset += Second.Length;
        Third.CopyTo(destination[offset..]);
    }
}
