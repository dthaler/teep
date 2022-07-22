using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TamCsOverCppShim;

namespace TamService
{
    public class Program
    {
        const string DEFAULT_MANIFEST_DIRECTORY = "../../../manifests";
        const bool SIMULATED_TEE = true;

        public static int Main(string[] args)
        {
            int err = ManagedType.TamBrokerStart(DEFAULT_MANIFEST_DIRECTORY, SIMULATED_TEE);
            if (err != 0)
            {
                return err;
            }

            CreateHostBuilder(args).Build().Run();
            return 0;
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
