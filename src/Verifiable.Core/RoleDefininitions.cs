namespace Verifiable.Core
{       
    public class Holder
    {
        //These are used by Verified to call VerifiableDataRegistry.
        public void VerifyIdentifierKeys() { }
        public void VerifyIdentifierSchemas() { }
        public void VerifyIdetifiers(VerifiableDataRegistry verifificationRegister, Verifiable credential, string schema) { }
    }


    /// <summary>
    /// This issues <see cref="VerifiableCredential"/> to users. Often the user is the <see cref="Subject"/> but
    /// sometimes credentials are issued on behalf of somene. Like the <see cref="Subject"/> can be a vaccination
    /// certificate and the <see cref="Issuer"/> issues it to the that person. Another similar example is issuing
    /// a vaccination certification to a pet owner.
    /// </summary>
    public class Issuer
    {
        //This is called by someone to issue a credential to some Holder.
        public Verifiable Issue(string someParams) { return new Verifiable();  }
    }

    public class Subject { }

    public class Verifier
    {
        //This is called by holder.
        public void PresentCrential(Presentation presentation) { }

        //These are used by Verified to call VerifiableDataRegistry.
        public void VerifyIdentifierKeys() { }
        public void VerifyIdentifierSchemas() { }
        public void VerifyIdetifiers(VerifiableDataRegistry verifificationRegister, Verifiable credential, string schema) { }
    }


    public class VerifiableDataRegistry { }

    //An extra piece...
    public class Wallet
    {
        //These are used by the holder.
        public void StoreCredential(Verifiable credential) { }
        public Verifiable RetrieveCredential(string id) { return new Verifiable(); }
    }
}
