using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DaemonApp
{
    class Program
    {
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string certName = ConfigurationManager.AppSettings["ida:CertName"];

        static string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        private static HttpClient httpClient = new HttpClient();
        private static AuthenticationContext authContext = new AuthenticationContext(authority);
        private static ClientAssertionCertificate certCred = null;

        private static string audienceUri = ConfigurationManager.AppSettings["ida:AudienceUri"];

        private static string graphUrl = "https://graph.microsoft.com/v1.0/users";

        static void Main(string[] args)
        {
            var result = CallAPI().Result;
            Console.WriteLine(result);
        }

        static async Task<string> CallAPI()
        {
            AuthenticationResult result = await GetAccessToken(audienceUri);
            if (result == null)
            {
                Console.WriteLine("Canceling attempt to call graph.\n");
                return null;
            }
            else
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                HttpResponseMessage response = await httpClient.GetAsync(graphUrl);
                if (response.IsSuccessStatusCode == true)
                {
                    return await response.Content.ReadAsStringAsync();
                }
                else
                {
                    Console.WriteLine("Failed to call graph.\nError:  {0}\n", response.ReasonPhrase);
                    return null;
                }
            }
        }

        private static async Task<AuthenticationResult> GetAccessToken(string resourceId)
        {
            AuthenticationResult result = null;
            int retryCount = 0;
            bool retry = false;

            // Initialize the Certificate Credential to be used by ADAL.
            X509Certificate2 cert = ReadCertificateFromStore(certName);
            if (cert == null)
            {
                Console.WriteLine($"Cannot find active certificate '{certName}' in certificates for current user. Please check configuration");
            }

            certCred = new ClientAssertionCertificate(clientId, cert);

            do
            {
                retry = false;

                try
                {
                    result = await authContext.AcquireTokenAsync(resourceId, certCred);
                }
                catch (AdalException ex)
                {
                    if (ex.ErrorCode == "temporarily_unavailable")
                    {
                        retry = true;
                        retryCount++;
                        Thread.Sleep(3000);
                    }

                    Console.WriteLine(
                        String.Format("An error occurred while acquiring a token\nTime: {0}\nError: {1}\nRetry: {2}\n",
                        DateTime.Now.ToString(),
                        ex.ToString(),
                        retry.ToString()));
                }

            } while ((retry == true) && (retryCount < 3));
            return result;
        }

        private static X509Certificate2 ReadCertificateFromStore(string certName)
        {
            X509Certificate2 cert = null;
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = store.Certificates;

            // Find unexpired certificates.
            X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

            // From the collection of unexpired certificates, find the ones with the correct name.
            X509Certificate2Collection signingCert = currentCerts.Find(
                X509FindType.FindBySubjectDistinguishedName, certName, false);

            // Return the first certificate in the collection, has the right name and is current.
            cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();
            store.Close();
            return cert;
        }
    
    }
}
