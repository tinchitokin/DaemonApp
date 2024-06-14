using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Identity.Client;
using System;
using System.Configuration;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DaemonApp
{
    class Program
    {
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string keyVaultUri = ConfigurationManager.AppSettings["ida:KeyVaultUri"];
        private static string certName = ConfigurationManager.AppSettings["ida:CertName"];

        static string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        private static HttpClient httpClient = new HttpClient();

        private static string audienceUri = ConfigurationManager.AppSettings["ida:AudienceUri"];

        private static string graphUrl = "https://graph.microsoft.com/v1.0/users";

        static void Main(string[] args)
        {
            try
            {
                var result = CallAPI().Result;
                Console.WriteLine(result);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            Console.ReadKey();
        }

        static async Task<string> CallAPI()
        {
            AuthenticationResult result = await GetAccessTokenWithMSAL(audienceUri);
            if (result == null)
            {
                Console.WriteLine("Canceling attempt to call graph.\n");
                return null;
            }
            else
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                HttpResponseMessage response = await httpClient.GetAsync(graphUrl);
                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync();
                }
                else
                {
                    Console.WriteLine($"Failed to call graph.\nError:  {response.ReasonPhrase}\n");
                    return null;
                }
            }
        }


        private static async Task<AuthenticationResult> GetAccessTokenWithMSAL(string resourceId)
        {
            X509Certificate2 cert = await GetCertificateFromKeyVault(certName);
            if (cert == null)
            {
                Console.WriteLine($"Cannot find active certificate '{certName}' in Azure Key Vault. Please check configuration");
                return null;
            }

            IConfidentialClientApplication app = ConfidentialClientApplicationBuilder.Create(clientId)
                .WithAuthority(new Uri(authority))
                .WithCertificate(cert)
                .Build();

            string[] scopes = new string[] { $"{resourceId}/.default" };

            AuthenticationResult result = await app.AcquireTokenForClient(scopes).ExecuteAsync();

            return result;
        }


        //private static async Task<AuthenticationResult> GetAccessToken(string resourceId)
        //{
        //    AuthenticationResult result = null;
        //    int retryCount = 0;
        //    bool retry = false;

        //    // Initialize the Certificate Credential to be used by ADAL.
        //    X509Certificate2 cert = await GetCertificateFromKeyVault(certName);
        //    if (cert == null)
        //    {
        //        Console.WriteLine($"Cannot find active certificate '{certName}' in Azure Key Vault. Please check configuration");
        //    }

        //    certCred = new ClientAssertionCertificate(clientId, cert);

        //    do
        //    {
        //        retry = false;

        //        try
        //        {
        //            result = await authContext.AcquireTokenAsync(resourceId, certCred);
        //        }
        //        catch (AdalException ex)
        //        {
        //            if (ex.ErrorCode == "temporarily_unavailable")
        //            {
        //                retry = true;
        //                retryCount++;
        //                Thread.Sleep(3000);
        //            }

        //            Console.WriteLine(
        //                String.Format("An error occurred while acquiring a token\nTime: {0}\nError: {1}\nRetry: {2}\n",
        //                DateTime.Now.ToString(),
        //                ex.ToString(),
        //                retry.ToString()));
        //        }

        //    } while ((retry == true) && (retryCount < 3));
        //    return result;
        //}

        private static async Task<X509Certificate2> GetCertificateFromKeyVault(string certName)
        {
            var keyVaultUriBuilder = new UriBuilder(keyVaultUri);
            var keyVaultUrl = keyVaultUriBuilder.Uri;

            var credential = new DefaultAzureCredential();
            var certificateClient = new CertificateClient(keyVaultUrl, credential);

            try
            {
                // Retrieve the certificate with its policy directly
                KeyVaultCertificateWithPolicy certificate = await certificateClient.GetCertificateAsync(certName);

                // Check if the certificate contains a private key
                if (certificate.Policy.Exportable == true)
                {
                    // Download the certificate's secret which contains the private key
                    var secretClient = new SecretClient(keyVaultUrl, credential);
                    KeyVaultSecret secret = await secretClient.GetSecretAsync(certName);

                    // Convert the secret value to a byte array and create an X509Certificate2 object
                    byte[] certBytes = Convert.FromBase64String(secret.Value);
                    return new X509Certificate2(certBytes, (string)null, X509KeyStorageFlags.MachineKeySet);
                }
                else
                {
                    Console.WriteLine("The certificate does not contain a private key or is not marked as exportable.");
                    return null;
                }
            }
            catch (RequestFailedException ex)
            {
                Console.WriteLine($"An error occurred while retrieving the certificate: {ex.Message}");
                return null;
            }
        }

    }
}
