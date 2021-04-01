
using ElectionGuard.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ElectionGuard.Data
{
    public static class ConfigureData
    {
        public static void AddDataServices(this IServiceCollection services, HostBuilderContext context)
        {
            services.AddOptions<DataOptions>().Bind(context.Configuration.GetSection(DataOptions.Data));
            services.AddSingleton<IDataService, JsonDataService>();
        }
    }

}