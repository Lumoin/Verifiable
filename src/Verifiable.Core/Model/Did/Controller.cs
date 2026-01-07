using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a controller of a controlled identifier document as defined in the
    /// W3C Controlled Identifiers v1.0 specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A controller is an entity capable of making changes to the controlled identifier
    /// document. The controller has the authority to update, add, or remove verification
    /// methods and services from the document.
    /// </para>
    /// <para>
    /// The controller value is a URL that identifies the controlling entity, typically
    /// another controlled identifier (DID) that can be dereferenced to obtain verification
    /// methods for authenticating changes to the document.
    /// </para>
    /// <para>
    /// When the <c>controller</c> property is not present in a document, the subject
    /// (<c>id</c>) is implicitly the controller. Proofs that satisfy the document's
    /// verification methods are taken as cryptographic assurance that the controller
    /// created those proofs.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/cid-1.0/#controllers">CID 1.0 §2.1.2 Controllers</see>
    /// and <see href="https://www.w3.org/TR/did-core/#did-controller">DID Core §5.1.2 DID Controller</see>.
    /// </para>
    /// </remarks>
    [DebuggerDisplay("Controller(Did = {Did})")]
    public sealed class Controller: IEquatable<Controller>
    {
        /// <summary>
        /// The URL identifying the controller.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is typically a DID (e.g., <c>did:example:controller</c>) that can be
        /// dereferenced to obtain verification methods for authenticating control operations.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#controllers">CID 1.0 §2.1.2 Controllers</see>.
        /// </para>
        /// </remarks>
        public string Did { get; }


        /// <summary>
        /// Creates a new controller with the specified identifier.
        /// </summary>
        /// <param name="did">The URL identifying the controller.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="did"/> is null.</exception>
        public Controller(string did)
        {
            ArgumentNullException.ThrowIfNull(did);
            Did = did;
        }


        /// <summary>
        /// Implicitly converts a <see cref="Controller"/> to its string representation.
        /// </summary>
        /// <param name="controller">The controller to convert.</param>
        public static implicit operator string(Controller controller) => controller.Did;


        /// <summary>
        /// Explicitly converts a string to a <see cref="Controller"/>.
        /// </summary>
        /// <param name="did">The controller identifier.</param>
        public static explicit operator Controller(string did) => new(did);


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(Controller? other)
        {
            if(other is null)
            {
                return false;
            }

            if(ReferenceEquals(this, other))
            {
                return true;
            }

            return string.Equals(Did, other.Did, StringComparison.Ordinal);
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) =>
            obj is Controller controller && Equals(controller);


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(Controller? left, Controller? right)
        {
            if(left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(Controller? left, Controller? right) => !(left == right);


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => Did.GetHashCode(StringComparison.Ordinal);


        /// <inheritdoc/>
        public override string ToString() => Did;
    }
}