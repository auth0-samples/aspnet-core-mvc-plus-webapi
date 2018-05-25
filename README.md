# JWT and Cookie authentication on the same project

We have samples in places showing how to do [cookie authentication for regular web applications](https://github.com/auth0-samples/auth0-aspnetcore-sample)
and [JWT token bearer authentication for WebAPI-type projects](https://github.com/auth0-samples/auth0-aspnetcore-sample) separately.

There can be cases however where you decide to have only one project/domain that serves both a
regular web application as well as an API.

This sample shows how to setup a project that has both a regular web site and an API. 
The API can be consumed by the web application with cookie authentication but can 
also be consumed by external clients using JWT tokens obtained from the identity provider.

This sample is for .Net Core 2. If you want a sample for .Net Core 1, look at the `v1` branch.

## Basics

The WebAPI part is modeled as an [API in Auth0](https://auth0.com/docs/api-auth), with its own API identifier. 
It should be configured with RS256 token signing.

The web site is configured as a regular-web-app-type client in Auth0.


## Getting Started

To run this quickstart you can fork and clone this repo.

### Create the web client
Create a client in Auth0, giving it a name and selecting the **Regular Web Applications** type. 
You can skip the **Quick Start** (you will be using this instructions instead). 

Enable one or more connections for the client.

You will need to add a callback URL to the list of Allowed URLs for your application. The Callback URL for the project is http://localhost:60856/signin-auth0 if you use IIS Express, or http://localhost:5000/signin-auth0 if you use Kestrel, so be sure to add this to the Allowed Callback URLs section of your application.

The ASP.NET Core OpenID Connect (OIDC) middleware which will be used to authenticate the user, requires that the JSON Web Token (JWT) be signed with an asymmetric key. To configure this go to the settings for your application in the Auth0 Dashboard, scroll down and click on Show Advanced Settings. Go to the OAuth tab and set the JsonWebToken Signature Algorithm to **RS256**.

Save all the changes.

### Create the API

Create an API in Auth0 and give it a unique identifier. 


### Configure the application

Be sure to update the `appsettings.json` with your Auth0 settings:

```json
{
  "Auth0": {
    "Domain": "Your Auth0 domain",
    "ClientId": "Your Auth0 Client Id",
    "ClientSecret": "Your Auth0 Client Secret",
    "ApiIdentifier": "your API identifier"
  } 
}
```

Then restore the NuGet packages and run the application:

```bash
# Install the dependencies
dotnet restore

# Run
dotnet run
```

You can shut down the web server manually by pressing Ctrl-C.

The website allows you to log in. Once logged in, you can access both an interactive
endpoint (/Account/Claims) and an API endpoint (/api/claims) to see your claims, as 
provided by cookie authentication.


You can also test the API endpoint `/api/claims` as an external client, by obtaining
first an access token. You can obtain one easily from the **Test** tab in the API settings. 
Once you have the access token, you can try the endpoint from Postman as explained in https://auth0.com/docs/quickstart/backend/aspnet-core-webapi/01-authentication#4-testing-your-api-in-postman.

## Important Snippets

The API will accept both a cookie from an authenticated user of the app, 
as well as a JWT token.

### 1. Add the Cookie and OIDC Middleware

We configure the cookie middleware in a fairly standard way, with one difference:
by default the cookie middleware will challenge the OIDC middleware for a login if the
user tries to access a protected resource. 
For API calls, we don't want a redirect to the login page, instead we need a simple
401 response. We get that by handling the `OnRedirectToLogin`, using some custom logic
to detect an API call. 

```csharp
seerices.AddCookie(options => {
    options.Events.OnRedirectToLogin = ctx =>
        {
            // if it is an ajax/api request, don't redirect
            // to login page.
            if (!(IsAjaxRequest(ctx.Request) || IsApiRequest(ctx.Request)))
            {
                ctx.Response.Redirect(ctx.RedirectUri);
                return Task.CompletedTask;
            }
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return ctx.Response.WriteAsync("Unauthorized");
        };
})
```

The `IsAjaxRequest` and `IsApiRequest` are provided as sample, feel free
to customize the logic as desired.

```csharp
private static bool IsAjaxRequest(HttpRequest request)
{
    var query = request.Query;
    if ((query != null) && (query["X-Requested-With"] == "XMLHttpRequest"))
    {
        return true;
    }
    IHeaderDictionary headers = request.Headers;
    return ((headers != null) && (headers["X-Requested-With"] == "XMLHttpRequest"));
}

private static bool IsApiRequest(HttpRequest request)
{
    return request.Path.StartsWithSegments(new PathString("/api"));
}
```

### 2. Add the JWT Middleware

The middleware will look for a valid JWT token in the Authentication
header, and set up a corresponding Principal if found.

```csharp
services.AddJwtBearer(options => {
    options.Authority = $"https://{Configuration["Auth0:Domain"]}";
    options.Audience = Configuration["Auth0:ApiIdentifier"];
});
```

### 3. Configure authorization in your API controllers/actions

By default, the `AuthorizeAttribute` will use the first authentication scheme defined (Cookies). You can list
multiple authentication schemes (either comma-separated or using multiple attributes) to allow both cookies and JWT bearer:

```csharp
// This API will accept both cookie authentication and JWT bearer authentication.
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]         
[HttpGet]
[Route("ping/secure")]
public string PingSecured()
{
    return "All good " + this.User.FindFirst(ClaimTypes.NameIdentifier).Value + ". You only get this message if you are authenticated.";
}
```