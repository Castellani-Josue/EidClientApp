using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EidClientApp.Models
{
    public class EidAuthRequest
    {
        public string nationalId { get; set; }
        public string certificate { get; set; }
        public string signature { get; set; }
    }
}
