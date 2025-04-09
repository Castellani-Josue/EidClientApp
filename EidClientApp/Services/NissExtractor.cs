using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EidClientApp.Services
{
    public class NissExtractor
    {
        public string ExtractFromCertificate(byte[] certBytes)
        {
            string niss = "";
            try
            {
                // On crée un X509Certificate2 pour analyser le sujet
                var cert = new X509Certificate2(certBytes);
                Console.WriteLine(cert.ToString(true));
                string subject = cert.Subject;
                // Recherche du champ "SN=" dans le sujet
                string[] parts = subject.Split(',');
                foreach (var part in parts)
                {
                    var trimmedPart = part.Trim();
                    if (trimmedPart.StartsWith("SERIALNUMBER="))
                    {
                        niss = trimmedPart.Substring("SERIALNUMBER=".Length);
                        break;
                    }
                }
                Console.WriteLine($"NISS trouvé dans le certificat : {niss}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors de l'extraction du NISS : {ex.Message}");
            }
            return niss;
        }
    }
}
