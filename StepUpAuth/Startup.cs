using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using StepUpAuth.Models;

namespace StepUpAuth
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddUserSecrets("f8de2b24-095e-4d0f-91aa-6151ac9416e3")
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = Policies.SignUpInBasic;
            })
            .AddOpenIdConnect(Policies.SignUpInBasic, options =>
            {
                BasicOpenIdConnectOptions(options, Configuration);
            })
            .AddOpenIdConnect(Policies.SignUpInStepUp, options =>
            {
                StepUpOpenIdConnectOptions(options, Configuration);
            })
            .AddCookie();

            services.AddMvc();

            // Adds a default in-memory implementation of IDistributedCache.
            services.AddDistributedMemoryCache();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromHours(1);
                options.CookieHttpOnly = true;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseSession();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private void BasicOpenIdConnectOptions(OpenIdConnectOptions options, IConfigurationRoot configuration)
        {
            var tenant = configuration["Authentication:Tenant"];
            var clientId = configuration[string.Format("Authentication:{0}:ClientId", Policies.SignUpInBasic)];
            var authority = string.Format("https://login.microsoftonline.com/tfp/{0}/{1}/v2.0", tenant, Policies.SignUpInBasic);
            var redirectUri = configuration[string.Format("Authentication:{0}:RedirectUri", Policies.SignUpInBasic)];
            var clientSecret = configuration[string.Format("Authentication:{0}:ClientSecret", Policies.SignUpInBasic)];
            
            options.ClientId = clientId;
            options.Authority = authority;
            options.CallbackPath = string.Format("/signin/{0}", Policies.SignUpInBasic);
            options.SignedOutRedirectUri = "/";
            options.UseTokenLifetime = true;
            options.TokenValidationParameters.NameClaimType = "name";

            options.Events = new OpenIdConnectEvents()
            {
                OnRedirectToIdentityProvider = context =>
                {
                    if (context.Properties.Items.TryGetValue("Policy", out var policy) && !policy.Equals(Policies.SignUpInBasic))
                    {
                        context.ProtocolMessage.Scope = OpenIdConnectScope.OpenIdProfile;
                        context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                        context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.ToLower().Replace(Policies.SignUpInBasic.ToLower(), policy.ToLower());
                        context.Properties.Items.Remove("Policy");
                    }
                    else
                    {
                        context.ProtocolMessage.Scope += string.Format(" offline_access https://{0}/demoapp/basic", tenant);
                        context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                    }
                    return Task.FromResult(0);
                },
                OnRemoteFailure = context =>
                {
                    context.HandleResponse();
                    // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
                    // because password reset is not supported by a "sign-up or sign-in policy"
                    if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("AADB2C90118"))
                    {
                        // If the user clicked the reset password link, redirect to the reset password route
                        context.Response.Redirect("/Auth/ResetPassword");
                    }
                    else if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied"))
                    {
                        context.Response.Redirect("/");
                    }
                    else
                    {
                        context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
                    }
                    return Task.FromResult(0);
                },
                OnAuthorizationCodeReceived = async context =>
                {
                    // Use MSAL to swap the code for an access token
                    // Extract the code from the response notification
                    var code = context.ProtocolMessage.Code;

                    string signedInUserID = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                    TokenCache userTokenCache = new MSALSessionCache(signedInUserID, context.HttpContext).GetMsalCacheInstance();
                    ConfidentialClientApplication cca = new ConfidentialClientApplication(clientId, authority, redirectUri, new ClientCredential(clientSecret), userTokenCache, null);
                    try
                    {
                        AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, new string[] { string.Format("https://{0}/demoapp/basic", tenant) });
                        
                        context.HandleCodeRedemption(result.AccessToken, result.IdToken);
                    }
                    catch (Exception ex)
                    {
                        //TODO: Handle
                        throw;
                    }
                }
            };
        }

        private void StepUpOpenIdConnectOptions(OpenIdConnectOptions options, IConfigurationRoot configuration)
        {
            var tenant = configuration["Authentication:Tenant"];
            var clientId = configuration[string.Format("Authentication:{0}:ClientId", Policies.SignUpInStepUp)];
            var authority = string.Format("https://login.microsoftonline.com/tfp/{0}/{1}/v2.0", tenant, Policies.SignUpInStepUp);
            
            options.ClientId = clientId;
            options.Authority = authority;
            options.CallbackPath = string.Format("/signin/{0}", Policies.SignUpInStepUp);
            options.SignedOutRedirectUri = "/";
            options.UseTokenLifetime = true;
            options.TokenValidationParameters.NameClaimType = "name";

            options.Events = new OpenIdConnectEvents()
            {
                OnRedirectToIdentityProvider = context =>
                {
                    context.ProtocolMessage.Prompt = "login";
                    return Task.FromResult(0);
                }
            };
        }
    }
}
