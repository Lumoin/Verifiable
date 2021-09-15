using System.Collections.Generic;

namespace Verifiable.Core
{
    //https://www.w3.org/TR/vc-data-model/#types
    //All of these types MUST have type information.

    public class Verifiable
    {
        //TODO: The same context as with DIDs?
        /// <summary>
        /// Abc.
        /// </summary>
        public List<string>? Context { get; set; }

        /// <summary>
        /// Each presentation or credential must have a type property.
        /// Look more at <a href="https://w3c.github.io/vc-data-model/#types">types</a>.
        /// </summary>
        public List<string> Type {  get; set; } = new List<string>();
    }


    public class VerifiableCredential: Verifiable
    {
        //TODO: Consider using a type for identifiers as they need to be of certain format (e.g. URI).
        /// <summary>
        /// The id property is intended to unambiguously refer to an object, such as a person, product, or organization.
        /// See more at <a href="https://w3c.github.io/vc-data-model/#identifier">identifiers</a>.
        /// </summary>
        /// <remarks>Identifiers might be harmful in scenarios where pseudonymity is required. Read more at
        /// <a href="https://w3c.github.io/vc-data-model/#identifier-based-correlation">identifier-Based Correlation</a>.</remarks>
        public string? Id {  get; set; }

        //Issuer can be a URI or an embedded object. Like VerificationRelationship? F.ex. AssertionMethod.
        //A bit different, but apparently the shape of object can be anything as long as it has
        //an ID. Can it also have nested objects of significance to the data model
        //(e.g. not relevant just to business model).

        /// <summary>
        /// Must be an URI or an object containing an id property.
        /// See more at <a href="https://w3c.github.io/vc-data-model/#issuer">issuer</a>.
        /// </summary>
        public string Issuer { get; set; } = string.Empty;
    }


    /// <summary>
    /// Each <see cref="VerifiableCredential"/> must have <see cref="CredentialSubject"/> property.
    /// See more at <a href="https://w3c.github.io/vc-data-model/#credential-subject">credential subject</a>.
    /// </summary>
    public class CredentialSubject
    {

    }

    public class Presentation { }

    public class VerifiablePresentation: Presentation { }

    public class Proof { }

    public class CredentialStatus { }

    public class TermsOfUse { }

    public class Evidence { }
}
