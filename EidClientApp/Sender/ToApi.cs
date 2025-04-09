using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EidClientApp.Sender
{
    public class ToApi
    {
        public static async Task SendToApi(string certB64, string signatureB64)
        {
            var client = new HttpClient();

            var content = new StringContent($@"
            {{
                ""certificate"": ""{certB64}"",
                ""signature"": ""{signatureB64}"",
                ""message"": ""authentifier moi""
            }}", Encoding.UTF8, "application/json");

            var response = await client.PostAsync("https://ton-api.be/authenticate", content);
            string result = await response.Content.ReadAsStringAsync();

            Console.WriteLine("Réponse de l’API : " + result);
        }
    }
}
