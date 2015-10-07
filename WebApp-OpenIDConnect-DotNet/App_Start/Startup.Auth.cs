//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

// The following using statements were added for this sample.
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Configuration;
using System.Globalization;
using System.Threading.Tasks;

namespace WebApp_OpenIDConnect_DotNet
{
    public partial class Startup
    {
        //
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The Metadata Address is used by the application to retrieve the signing keys used by Azure AD.
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Authority is the sign-in URL of the tenant.
        // The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        //
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        public void ConfigureAuth(IAppBuilder app)
        {
            //app.Run(context =>
            //{
            //    return Task.FromResult(0);
            //});
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions() { CookieName="MSRACookie"});
            
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = authority,
                    PostLogoutRedirectUri = postLogoutRedirectUri,
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = context =>
                        {
                            context.HandleResponse();
                            context.Response.Redirect("/Error?message=" + context.Exception.Message);
                            return Task.FromResult(0);
                        },
                        SecurityTokenReceived = context =>
                       {
                           return Task.FromResult(0);
                       },
                        AuthorizationCodeReceived = context =>
                         {
                             return Task.FromResult(0);
                         },
                        MessageReceived = context =>
                        {
                            return Task.FromResult(0);
                        }


                    }
                });

            app.Use((context, next) =>
            {
                if (!HttpContext.Current.Request.IsAuthenticated 
                    && HttpContext.Current.Session != null)
                    //&& !HttpContext.Current.Request.FilePath.ToLower().Contains("vsto") 
                    //&& !HttpContext.Current.Request.FilePath.ToLower().Contains("deploy")
                    //&& !HttpContext.Current.Request.FilePath.ToLower().Contains("manifest"))
                {
                    HttpContext.Current.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = HttpContext.Current.Request.FilePath }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
                }
                return next.Invoke();
            });


        }
    }
}