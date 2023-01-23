using ExampleEFMClient.EFM;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace ExampleEFMClient
{
  public class EFMClient
  {
    #region Private Properties

    private X509Certificate2 MessageSigningCertificate { get; set; }

    #endregion

    #region Constructors

    public EFMClient(X509Certificate2 certificate)
    {
      this.MessageSigningCertificate = certificate;

      // Uncomment this line to ignore server certificate errors
      // This is useful if running through a proxy (like Fiddler) to capture the message content
      //ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
    }

    public EFMClient(string pfxFilePath, string privateKeyPassword)
      : this(LoadCertificateFromFile(pfxFilePath, privateKeyPassword))
    {
    }

    public EFMClient(string subjectName)
      : this(LoadCertificateFromStore(subjectName))
    {
    }

    #endregion

    #region EFM Web Service Calls

    public AuthenticateResponseType AuthenticateUser(AuthenticateRequestType request)
    {
      EfmUserServiceClient userService = this.CreateUserService();
      userService.Open();
      System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      AuthenticateResponseType response = userService.AuthenticateUser(request);
      userService.Close();
      return response;
    }

    #endregion

    #region Private Methods - Create EFM Web Service Client

    protected EfmUserServiceClient CreateUserService()
    {
      EfmUserServiceClient client = new EfmUserServiceClient();
      client.ClientCredentials.ClientCertificate.Certificate = this.MessageSigningCertificate;
      return client;
    }

    #endregion

    #region Private Methods - Load Certificate

    private static X509Certificate2 LoadCertificateFromStore(string subjectName)
    {
      // Open the Certificates (Local Computer) --> Personal certificate store
      X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
      store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

      // Find a particular certificate by Subject Name
      X509Certificate2 certificate = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, false).OfType<X509Certificate2>().FirstOrDefault();

      // Close the certificate store
      store.Close();

      return certificate;
    }

    private static X509Certificate2 LoadCertificateFromFile(string pfxFilePath, string privateKeyPassword)
    {
      // Load the certificate from a file, specifying the password
      X509Certificate2 certificate = new X509Certificate2(pfxFilePath, privateKeyPassword);
      return certificate;
    }

    #endregion
  }
}
