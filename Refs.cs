// Microsoft.AspNetCore\Microsoft.AspNetCore\WebHost.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System;

namespace Microsoft.AspNetCore
{
	public static class WebHost
	{
		public static IWebHostBuilder CreateDefaultBuilder()
		{
			throw null;
		}

		public static IWebHostBuilder CreateDefaultBuilder(string[] args)
		{
			throw null;
		}

		public static IWebHostBuilder CreateDefaultBuilder<TStartup>(string[] args) where TStartup : class
		{
			throw null;
		}

		public static IWebHost Start(RequestDelegate app)
		{
			throw null;
		}

		public static IWebHost Start(Action<IRouteBuilder> routeBuilder)
		{
			throw null;
		}

		public static IWebHost Start(string url, RequestDelegate app)
		{
			throw null;
		}

		public static IWebHost Start(string url, Action<IRouteBuilder> routeBuilder)
		{
			throw null;
		}

		public static IWebHost StartWith(Action<IApplicationBuilder> app)
		{
			throw null;
		}

		public static IWebHost StartWith(string url, Action<IApplicationBuilder> app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore\Microsoft.Extensions.Hosting\GenericHostBuilderExtensions.cs
using Microsoft.AspNetCore.Hosting;
using System;

namespace Microsoft.Extensions.Hosting
{
	public static class GenericHostBuilderExtensions
	{
		public static IHostBuilder ConfigureWebHostDefaults(this IHostBuilder builder, Action<IWebHostBuilder> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\AntiforgeryOptions.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Antiforgery
{
	public class AntiforgeryOptions
	{
		public static readonly string DefaultCookiePrefix;

		public CookieBuilder Cookie
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public string FormFieldName
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public string HeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool SuppressXFrameOptionsHeader
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\AntiforgeryTokenSet.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Antiforgery
{
	public class AntiforgeryTokenSet
	{
		public string CookieToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string FormFieldName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string HeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string RequestToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AntiforgeryTokenSet(string requestToken, string cookieToken, string formFieldName, string headerName)
		{
		}
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\AntiforgeryValidationException.cs
using System;

namespace Microsoft.AspNetCore.Antiforgery
{
	public class AntiforgeryValidationException : Exception
	{
		public AntiforgeryValidationException(string message)
		{
		}

		public AntiforgeryValidationException(string message, Exception innerException)
		{
		}
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IAntiforgery.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Antiforgery
{
	public interface IAntiforgery
	{
		AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext);

		AntiforgeryTokenSet GetTokens(HttpContext httpContext);

		Task<bool> IsRequestValidAsync(HttpContext httpContext);

		void SetCookieTokenAndHeader(HttpContext httpContext);

		Task ValidateRequestAsync(HttpContext httpContext);
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IAntiforgeryAdditionalDataProvider.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Antiforgery
{
	public interface IAntiforgeryAdditionalDataProvider
	{
		string GetAdditionalData(HttpContext context);

		bool ValidateAdditionalData(HttpContext context, string additionalData);
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IAntiforgeryFeature.cs
namespace Microsoft.AspNetCore.Antiforgery
{
	internal interface IAntiforgeryFeature
	{
		AntiforgeryToken CookieToken
		{
			get;
			set;
		}

		bool HaveDeserializedCookieToken
		{
			get;
			set;
		}

		bool HaveDeserializedRequestToken
		{
			get;
			set;
		}

		bool HaveGeneratedNewCookieToken
		{
			get;
			set;
		}

		bool HaveStoredNewCookieToken
		{
			get;
			set;
		}

		AntiforgeryToken NewCookieToken
		{
			get;
			set;
		}

		string NewCookieTokenString
		{
			get;
			set;
		}

		AntiforgeryToken NewRequestToken
		{
			get;
			set;
		}

		string NewRequestTokenString
		{
			get;
			set;
		}

		AntiforgeryToken RequestToken
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IAntiforgeryTokenGenerator.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Antiforgery
{
	internal interface IAntiforgeryTokenGenerator
	{
		AntiforgeryToken GenerateCookieToken();

		AntiforgeryToken GenerateRequestToken(HttpContext httpContext, AntiforgeryToken cookieToken);

		bool IsCookieTokenValid(AntiforgeryToken cookieToken);

		bool TryValidateTokenSet(HttpContext httpContext, AntiforgeryToken cookieToken, AntiforgeryToken requestToken, out string message);
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IAntiforgeryTokenSerializer.cs
namespace Microsoft.AspNetCore.Antiforgery
{
	internal interface IAntiforgeryTokenSerializer
	{
		AntiforgeryToken Deserialize(string serializedToken);

		string Serialize(AntiforgeryToken token);
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IAntiforgeryTokenStore.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Antiforgery
{
	internal interface IAntiforgeryTokenStore
	{
		string GetCookieToken(HttpContext httpContext);

		Task<AntiforgeryTokenSet> GetRequestTokensAsync(HttpContext httpContext);

		void SaveCookieToken(HttpContext httpContext, string token);
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IClaimUidExtractor.cs
using System.Security.Claims;

namespace Microsoft.AspNetCore.Antiforgery
{
	internal interface IClaimUidExtractor
	{
		string ExtractClaimUid(ClaimsPrincipal claimsPrincipal);
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.Extensions.DependencyInjection\AntiforgeryServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Antiforgery;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class AntiforgeryServiceCollectionExtensions
	{
		public static IServiceCollection AddAntiforgery(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddAntiforgery(this IServiceCollection services, Action<AntiforgeryOptions> setupAction)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\AccessDeniedContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AccessDeniedContext : HandleRequestContext<RemoteAuthenticationOptions>
	{
		public PathString AccessDeniedPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthenticationProperties Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ReturnUrl
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ReturnUrlParameter
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AccessDeniedContext(HttpContext context, AuthenticationScheme scheme, RemoteAuthenticationOptions options)
			: base((HttpContext)null, (AuthenticationScheme)null, (RemoteAuthenticationOptions)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\AuthenticationBuilder.cs
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationBuilder
	{
		public virtual IServiceCollection Services
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticationBuilder(IServiceCollection services)
		{
		}

		public virtual AuthenticationBuilder AddPolicyScheme(string authenticationScheme, string displayName, Action<PolicySchemeOptions> configureOptions)
		{
			throw null;
		}

		public virtual AuthenticationBuilder AddRemoteScheme<TOptions, THandler>(string authenticationScheme, string displayName, Action<TOptions> configureOptions) where TOptions : RemoteAuthenticationOptions, new()where THandler : RemoteAuthenticationHandler<TOptions>
		{
			throw null;
		}

		public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, Action<TOptions> configureOptions) where TOptions : AuthenticationSchemeOptions, new()where THandler : AuthenticationHandler<TOptions>
		{
			throw null;
		}

		public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, string displayName, Action<TOptions> configureOptions) where TOptions : AuthenticationSchemeOptions, new()where THandler : AuthenticationHandler<TOptions>
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\AuthenticationHandler.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class AuthenticationHandler<TOptions> : IAuthenticationHandler where TOptions : AuthenticationSchemeOptions, new()
	{
		protected virtual string ClaimsIssuer
		{
			get
			{
				throw null;
			}
		}

		protected ISystemClock Clock
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HttpContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected string CurrentUri
		{
			get
			{
				throw null;
			}
		}

		protected virtual object Events
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected ILogger Logger
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TOptions Options
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected IOptionsMonitor<TOptions> OptionsMonitor
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected PathString OriginalPath
		{
			get
			{
				throw null;
			}
		}

		protected PathString OriginalPathBase
		{
			get
			{
				throw null;
			}
		}

		protected HttpRequest Request
		{
			get
			{
				throw null;
			}
		}

		protected HttpResponse Response
		{
			get
			{
				throw null;
			}
		}

		public AuthenticationScheme Scheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected UrlEncoder UrlEncoder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected AuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
		{
		}

		[DebuggerStepThrough]
		public Task<AuthenticateResult> AuthenticateAsync()
		{
			throw null;
		}

		protected string BuildRedirectUri(string targetPath)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task ChallengeAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected virtual Task<object> CreateEventsAsync()
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task ForbidAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected abstract Task<AuthenticateResult> HandleAuthenticateAsync();

		protected Task<AuthenticateResult> HandleAuthenticateOnceAsync()
		{
			throw null;
		}

		[DebuggerStepThrough]
		protected Task<AuthenticateResult> HandleAuthenticateOnceSafeAsync()
		{
			throw null;
		}

		protected virtual Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected virtual Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
		{
			throw null;
		}

		[DebuggerStepThrough]
		protected virtual Task InitializeEventsAsync()
		{
			throw null;
		}

		protected virtual Task InitializeHandlerAsync()
		{
			throw null;
		}

		protected virtual string ResolveTarget(string scheme)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\AuthenticationMiddleware.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationMiddleware
	{
		public IAuthenticationSchemeProvider Schemes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthenticationMiddleware(RequestDelegate next, IAuthenticationSchemeProvider schemes)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\AuthenticationSchemeOptions.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationSchemeOptions
	{
		public string ClaimsIssuer
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public object Events
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Type EventsType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardAuthenticate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardChallenge
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardDefault
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Func<HttpContext, string> ForwardDefaultSelector
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardForbid
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardSignIn
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardSignOut
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual void Validate()
		{
		}

		public virtual void Validate(string scheme)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\Base64UrlTextEncoder.cs
namespace Microsoft.AspNetCore.Authentication
{
	public static class Base64UrlTextEncoder
	{
		public static byte[] Decode(string text)
		{
			throw null;
		}

		public static string Encode(byte[] data)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\BaseContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
	{
		public HttpContext HttpContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TOptions Options
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HttpRequest Request
		{
			get
			{
				throw null;
			}
		}

		public HttpResponse Response
		{
			get
			{
				throw null;
			}
		}

		public AuthenticationScheme Scheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected BaseContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\HandleRequestContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class HandleRequestContext<TOptions> : BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
	{
		public HandleRequestResult Result
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		protected HandleRequestContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
			: base((HttpContext)null, (AuthenticationScheme)null, (TOptions)null)
		{
		}

		public void HandleResponse()
		{
		}

		public void SkipHandler()
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\HandleRequestResult.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class HandleRequestResult : AuthenticateResult
	{
		public bool Handled
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool Skipped
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public new static HandleRequestResult Fail(Exception failure)
		{
			throw null;
		}

		public new static HandleRequestResult Fail(Exception failure, AuthenticationProperties properties)
		{
			throw null;
		}

		public new static HandleRequestResult Fail(string failureMessage)
		{
			throw null;
		}

		public new static HandleRequestResult Fail(string failureMessage, AuthenticationProperties properties)
		{
			throw null;
		}

		public static HandleRequestResult Handle()
		{
			throw null;
		}

		public new static HandleRequestResult NoResult()
		{
			throw null;
		}

		public static HandleRequestResult SkipHandler()
		{
			throw null;
		}

		public new static HandleRequestResult Success(AuthenticationTicket ticket)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\IDataSerializer.cs
namespace Microsoft.AspNetCore.Authentication
{
	public interface IDataSerializer<TModel>
	{
		TModel Deserialize(byte[] data);

		byte[] Serialize(TModel model);
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\ISecureDataFormat.cs
namespace Microsoft.AspNetCore.Authentication
{
	public interface ISecureDataFormat<TData>
	{
		string Protect(TData data);

		string Protect(TData data, string purpose);

		TData Unprotect(string protectedText);

		TData Unprotect(string protectedText, string purpose);
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\ISystemClock.cs
using System;

namespace Microsoft.AspNetCore.Authentication
{
	public interface ISystemClock
	{
		DateTimeOffset UtcNow
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\JsonDocumentAuthExtensions.cs
using System.Text.Json;

namespace Microsoft.AspNetCore.Authentication
{
	public static class JsonDocumentAuthExtensions
	{
		public static string GetString(this JsonElement element, string key)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\PolicySchemeHandler.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public class PolicySchemeHandler : SignInAuthenticationHandler<PolicySchemeOptions>
	{
		public PolicySchemeHandler(IOptionsMonitor<PolicySchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base((IOptionsMonitor<PolicySchemeOptions>)null, (ILoggerFactory)null, (UrlEncoder)null, (ISystemClock)null)
		{
		}

		protected override Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			throw null;
		}

		protected override Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
		{
			throw null;
		}

		protected override Task HandleSignOutAsync(AuthenticationProperties properties)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\PolicySchemeOptions.cs
namespace Microsoft.AspNetCore.Authentication
{
	public class PolicySchemeOptions : AuthenticationSchemeOptions
	{
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\PrincipalContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class PrincipalContext<TOptions> : PropertiesContext<TOptions> where TOptions : AuthenticationSchemeOptions
	{
		public virtual ClaimsPrincipal Principal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected PrincipalContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties properties)
			: base((HttpContext)null, (AuthenticationScheme)null, (TOptions)null, (AuthenticationProperties)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\PropertiesContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class PropertiesContext<TOptions> : BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
	{
		public virtual AuthenticationProperties Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		protected PropertiesContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties properties)
			: base((HttpContext)null, (AuthenticationScheme)null, (TOptions)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\PropertiesDataFormat.cs
using Microsoft.AspNetCore.DataProtection;

namespace Microsoft.AspNetCore.Authentication
{
	public class PropertiesDataFormat : SecureDataFormat<AuthenticationProperties>
	{
		public PropertiesDataFormat(IDataProtector protector)
			: base((IDataSerializer<AuthenticationProperties>)null, (IDataProtector)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\PropertiesSerializer.cs
using System.IO;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class PropertiesSerializer : IDataSerializer<AuthenticationProperties>
	{
		public static PropertiesSerializer Default
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public virtual AuthenticationProperties Deserialize(byte[] data)
		{
			throw null;
		}

		public virtual AuthenticationProperties Read(BinaryReader reader)
		{
			throw null;
		}

		public virtual byte[] Serialize(AuthenticationProperties model)
		{
			throw null;
		}

		public virtual void Write(BinaryWriter writer, AuthenticationProperties properties)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RedirectContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class RedirectContext<TOptions> : PropertiesContext<TOptions> where TOptions : AuthenticationSchemeOptions
	{
		public string RedirectUri
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RedirectContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties properties, string redirectUri)
			: base((HttpContext)null, (AuthenticationScheme)null, (TOptions)null, (AuthenticationProperties)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RemoteAuthenticationContext.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class RemoteAuthenticationContext<TOptions> : HandleRequestContext<TOptions> where TOptions : AuthenticationSchemeOptions
	{
		public ClaimsPrincipal Principal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual AuthenticationProperties Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected RemoteAuthenticationContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties properties)
			: base((HttpContext)null, (AuthenticationScheme)null, (TOptions)null)
		{
		}

		public void Fail(Exception failure)
		{
		}

		public void Fail(string failureMessage)
		{
		}

		public void Success()
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RemoteAuthenticationEvents.cs
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public class RemoteAuthenticationEvents
	{
		public Func<AccessDeniedContext, Task> OnAccessDenied
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Func<RemoteFailureContext, Task> OnRemoteFailure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Func<TicketReceivedContext, Task> OnTicketReceived
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual Task AccessDenied(AccessDeniedContext context)
		{
			throw null;
		}

		public virtual Task RemoteFailure(RemoteFailureContext context)
		{
			throw null;
		}

		public virtual Task TicketReceived(TicketReceivedContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RemoteAuthenticationHandler.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class RemoteAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationHandler, IAuthenticationRequestHandler where TOptions : RemoteAuthenticationOptions, new()
	{
		protected new RemoteAuthenticationEvents Events
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		protected string SignInScheme
		{
			get
			{
				throw null;
			}
		}

		protected RemoteAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base((IOptionsMonitor<TOptions>)null, (ILoggerFactory)null, (UrlEncoder)null, (ISystemClock)null)
		{
		}

		protected override Task<object> CreateEventsAsync()
		{
			throw null;
		}

		protected virtual void GenerateCorrelationId(AuthenticationProperties properties)
		{
		}

		[DebuggerStepThrough]
		protected virtual Task<HandleRequestResult> HandleAccessDeniedErrorAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		[DebuggerStepThrough]
		protected override Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			throw null;
		}

		protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected abstract Task<HandleRequestResult> HandleRemoteAuthenticateAsync();

		[DebuggerStepThrough]
		public virtual Task<bool> HandleRequestAsync()
		{
			throw null;
		}

		public virtual Task<bool> ShouldHandleRequestAsync()
		{
			throw null;
		}

		protected virtual bool ValidateCorrelationId(AuthenticationProperties properties)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RemoteAuthenticationOptions.cs
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using System;
using System.Net.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class RemoteAuthenticationOptions : AuthenticationSchemeOptions
	{
		public PathString AccessDeniedPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public HttpClient Backchannel
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public HttpMessageHandler BackchannelHttpHandler
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan BackchannelTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public PathString CallbackPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookieBuilder CorrelationCookie
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IDataProtectionProvider DataProtectionProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public new RemoteAuthenticationEvents Events
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public TimeSpan RemoteAuthenticationTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ReturnUrlParameter
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool SaveTokens
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string SignInScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RemoteAuthenticationOptions()
		{
		}

		public override void Validate()
		{
		}

		public override void Validate(string scheme)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RemoteFailureContext.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class RemoteFailureContext : HandleRequestContext<RemoteAuthenticationOptions>
	{
		public Exception Failure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthenticationProperties Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RemoteFailureContext(HttpContext context, AuthenticationScheme scheme, RemoteAuthenticationOptions options, Exception failure)
			: base((HttpContext)null, (AuthenticationScheme)null, (RemoteAuthenticationOptions)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RequestPathBaseCookieBuilder.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class RequestPathBaseCookieBuilder : CookieBuilder
	{
		protected virtual string AdditionalPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\ResultContext.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class ResultContext<TOptions> : BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
	{
		public ClaimsPrincipal Principal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthenticationProperties Properties
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public AuthenticateResult Result
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected ResultContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
			: base((HttpContext)null, (AuthenticationScheme)null, (TOptions)null)
		{
		}

		public void Fail(Exception failure)
		{
		}

		public void Fail(string failureMessage)
		{
		}

		public void NoResult()
		{
		}

		public void Success()
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\SecureDataFormat.cs
using Microsoft.AspNetCore.DataProtection;

namespace Microsoft.AspNetCore.Authentication
{
	public class SecureDataFormat<TData> : ISecureDataFormat<TData>
	{
		public SecureDataFormat(IDataSerializer<TData> serializer, IDataProtector protector)
		{
		}

		public string Protect(TData data)
		{
			throw null;
		}

		public string Protect(TData data, string purpose)
		{
			throw null;
		}

		public TData Unprotect(string protectedText)
		{
			throw null;
		}

		public TData Unprotect(string protectedText, string purpose)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\SignInAuthenticationHandler.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class SignInAuthenticationHandler<TOptions> : SignOutAuthenticationHandler<TOptions>, IAuthenticationHandler, IAuthenticationSignInHandler, IAuthenticationSignOutHandler where TOptions : AuthenticationSchemeOptions, new()
	{
		public SignInAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base((IOptionsMonitor<TOptions>)null, (ILoggerFactory)null, (UrlEncoder)null, (ISystemClock)null)
		{
		}

		protected abstract Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties);

		public virtual Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\SignOutAuthenticationHandler.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class SignOutAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationHandler, IAuthenticationSignOutHandler where TOptions : AuthenticationSchemeOptions, new()
	{
		public SignOutAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base((IOptionsMonitor<TOptions>)null, (ILoggerFactory)null, (UrlEncoder)null, (ISystemClock)null)
		{
		}

		protected abstract Task HandleSignOutAsync(AuthenticationProperties properties);

		public virtual Task SignOutAsync(AuthenticationProperties properties)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\SystemClock.cs
using System;

namespace Microsoft.AspNetCore.Authentication
{
	public class SystemClock : ISystemClock
	{
		public DateTimeOffset UtcNow
		{
			get
			{
				throw null;
			}
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\TicketDataFormat.cs
using Microsoft.AspNetCore.DataProtection;

namespace Microsoft.AspNetCore.Authentication
{
	public class TicketDataFormat : SecureDataFormat<AuthenticationTicket>
	{
		public TicketDataFormat(IDataProtector protector)
			: base((IDataSerializer<AuthenticationTicket>)null, (IDataProtector)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\TicketReceivedContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class TicketReceivedContext : RemoteAuthenticationContext<RemoteAuthenticationOptions>
	{
		public string ReturnUri
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TicketReceivedContext(HttpContext context, AuthenticationScheme scheme, RemoteAuthenticationOptions options, AuthenticationTicket ticket)
			: base((HttpContext)null, (AuthenticationScheme)null, (RemoteAuthenticationOptions)null, (AuthenticationProperties)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\TicketSerializer.cs
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication
{
	public class TicketSerializer : IDataSerializer<AuthenticationTicket>
	{
		public static TicketSerializer Default
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public virtual AuthenticationTicket Deserialize(byte[] data)
		{
			throw null;
		}

		public virtual AuthenticationTicket Read(BinaryReader reader)
		{
			throw null;
		}

		protected virtual Claim ReadClaim(BinaryReader reader, ClaimsIdentity identity)
		{
			throw null;
		}

		protected virtual ClaimsIdentity ReadIdentity(BinaryReader reader)
		{
			throw null;
		}

		public virtual byte[] Serialize(AuthenticationTicket ticket)
		{
			throw null;
		}

		public virtual void Write(BinaryWriter writer, AuthenticationTicket ticket)
		{
		}

		protected virtual void WriteClaim(BinaryWriter writer, Claim claim)
		{
		}

		protected virtual void WriteIdentity(BinaryWriter writer, ClaimsIdentity identity)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Builder\AuthAppBuilderExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class AuthAppBuilderExtensions
	{
		public static IApplicationBuilder UseAuthentication(this IApplicationBuilder app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.Extensions.DependencyInjection\AuthenticationServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Authentication;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class AuthenticationServiceCollectionExtensions
	{
		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services)
		{
			throw null;
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, Action<AuthenticationOptions> configureOptions)
		{
			throw null;
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, string defaultScheme)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticateResult.cs
using System;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticateResult
	{
		public Exception Failure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public bool None
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public ClaimsPrincipal Principal
		{
			get
			{
				throw null;
			}
		}

		public AuthenticationProperties Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public bool Succeeded
		{
			get
			{
				throw null;
			}
		}

		public AuthenticationTicket Ticket
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		protected AuthenticateResult()
		{
		}

		public static AuthenticateResult Fail(Exception failure)
		{
			throw null;
		}

		public static AuthenticateResult Fail(Exception failure, AuthenticationProperties properties)
		{
			throw null;
		}

		public static AuthenticateResult Fail(string failureMessage)
		{
			throw null;
		}

		public static AuthenticateResult Fail(string failureMessage, AuthenticationProperties properties)
		{
			throw null;
		}

		public static AuthenticateResult NoResult()
		{
			throw null;
		}

		public static AuthenticateResult Success(AuthenticationTicket ticket)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationHttpContextExtensions.cs
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public static class AuthenticationHttpContextExtensions
	{
		public static Task<AuthenticateResult> AuthenticateAsync(this HttpContext context)
		{
			throw null;
		}

		public static Task<AuthenticateResult> AuthenticateAsync(this HttpContext context, string scheme)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context, AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context, string scheme)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context, string scheme, AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context, AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context, string scheme)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context, string scheme, AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task<string> GetTokenAsync(this HttpContext context, string tokenName)
		{
			throw null;
		}

		public static Task<string> GetTokenAsync(this HttpContext context, string scheme, string tokenName)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal, AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, string scheme, ClaimsPrincipal principal)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context, AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context, string scheme)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context, string scheme, AuthenticationProperties properties)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationOptions.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationOptions
	{
		public string DefaultAuthenticateScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string DefaultChallengeScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string DefaultForbidScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string DefaultScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string DefaultSignInScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string DefaultSignOutScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool RequireAuthenticatedSignIn
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IDictionary<string, AuthenticationSchemeBuilder> SchemeMap
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IEnumerable<AuthenticationSchemeBuilder> Schemes
		{
			get
			{
				throw null;
			}
		}

		public void AddScheme(string name, Action<AuthenticationSchemeBuilder> configureBuilder)
		{
		}

		public void AddScheme<THandler>(string name, string displayName) where THandler : IAuthenticationHandler
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationProperties.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationProperties
	{
		public bool? AllowRefresh
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? ExpiresUtc
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public bool IsPersistent
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? IssuedUtc
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IDictionary<string, string> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IDictionary<string, object> Parameters
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string RedirectUri
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public AuthenticationProperties()
		{
		}

		public AuthenticationProperties(IDictionary<string, string> items)
		{
		}

		public AuthenticationProperties(IDictionary<string, string> items, IDictionary<string, object> parameters)
		{
		}

		protected bool? GetBool(string key)
		{
			throw null;
		}

		protected DateTimeOffset? GetDateTimeOffset(string key)
		{
			throw null;
		}

		public T GetParameter<T>(string key)
		{
			throw null;
		}

		public string GetString(string key)
		{
			throw null;
		}

		protected void SetBool(string key, bool? value)
		{
		}

		protected void SetDateTimeOffset(string key, DateTimeOffset? value)
		{
		}

		public void SetParameter<T>(string key, T value)
		{
		}

		public void SetString(string key, string value)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationScheme.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationScheme
	{
		public string DisplayName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Type HandlerType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticationScheme(string name, string displayName, Type handlerType)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationSchemeBuilder.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationSchemeBuilder
	{
		public string DisplayName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Type HandlerType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticationSchemeBuilder(string name)
		{
		}

		public AuthenticationScheme Build()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationTicket.cs
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationTicket
	{
		public string AuthenticationScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ClaimsPrincipal Principal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticationProperties Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticationTicket(ClaimsPrincipal principal, AuthenticationProperties properties, string authenticationScheme)
		{
		}

		public AuthenticationTicket(ClaimsPrincipal principal, string authenticationScheme)
		{
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationToken.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationToken
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationTokenExtensions.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public static class AuthenticationTokenExtensions
	{
		public static Task<string> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string tokenName)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public static Task<string> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string scheme, string tokenName)
		{
			throw null;
		}

		public static IEnumerable<AuthenticationToken> GetTokens(this AuthenticationProperties properties)
		{
			throw null;
		}

		public static string GetTokenValue(this AuthenticationProperties properties, string tokenName)
		{
			throw null;
		}

		public static void StoreTokens(this AuthenticationProperties properties, IEnumerable<AuthenticationToken> tokens)
		{
		}

		public static bool UpdateTokenValue(this AuthenticationProperties properties, string tokenName, string tokenValue)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationFeature.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationFeature
	{
		PathString OriginalPath
		{
			get;
			set;
		}

		PathString OriginalPathBase
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationHandler.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationHandler
	{
		Task<AuthenticateResult> AuthenticateAsync();

		Task ChallengeAsync(AuthenticationProperties properties);

		Task ForbidAsync(AuthenticationProperties properties);

		Task InitializeAsync(AuthenticationScheme scheme, HttpContext context);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationHandlerProvider.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationHandlerProvider
	{
		Task<IAuthenticationHandler> GetHandlerAsync(HttpContext context, string authenticationScheme);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationRequestHandler.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationRequestHandler : IAuthenticationHandler
	{
		Task<bool> HandleRequestAsync();
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationSchemeProvider.cs
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationSchemeProvider
	{
		void AddScheme(AuthenticationScheme scheme);

		Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync();

		Task<AuthenticationScheme> GetDefaultAuthenticateSchemeAsync();

		Task<AuthenticationScheme> GetDefaultChallengeSchemeAsync();

		Task<AuthenticationScheme> GetDefaultForbidSchemeAsync();

		Task<AuthenticationScheme> GetDefaultSignInSchemeAsync();

		Task<AuthenticationScheme> GetDefaultSignOutSchemeAsync();

		Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync();

		Task<AuthenticationScheme> GetSchemeAsync(string name);

		void RemoveScheme(string name);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationService.cs
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationService
	{
		Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme);

		Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties);

		Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties);

		Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties);

		Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationSignInHandler.cs
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationSignInHandler : IAuthenticationHandler, IAuthenticationSignOutHandler
	{
		Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationSignOutHandler.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationSignOutHandler : IAuthenticationHandler
	{
		Task SignOutAsync(AuthenticationProperties properties);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IClaimsTransformation.cs
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IClaimsTransformation
	{
		Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AllowAnonymousAttribute.cs
using System;

namespace Microsoft.AspNetCore.Authorization
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
	public class AllowAnonymousAttribute : Attribute, IAllowAnonymous
	{
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationFailure.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationFailure
	{
		public bool FailCalled
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IEnumerable<IAuthorizationRequirement> FailedRequirements
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal AuthorizationFailure()
		{
		}

		public static AuthorizationFailure ExplicitFail()
		{
			throw null;
		}

		public static AuthorizationFailure Failed(IEnumerable<IAuthorizationRequirement> failed)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationHandler.cs
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public abstract class AuthorizationHandler<TRequirement> : IAuthorizationHandler where TRequirement : IAuthorizationRequirement
	{
		[DebuggerStepThrough]
		public virtual Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}

		protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement);
	}
	public abstract class AuthorizationHandler<TRequirement, TResource> : IAuthorizationHandler where TRequirement : IAuthorizationRequirement
	{
		[DebuggerStepThrough]
		public virtual Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}

		protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement, TResource resource);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationHandlerContext.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationHandlerContext
	{
		public virtual bool HasFailed
		{
			get
			{
				throw null;
			}
		}

		public virtual bool HasSucceeded
		{
			get
			{
				throw null;
			}
		}

		public virtual IEnumerable<IAuthorizationRequirement> PendingRequirements
		{
			get
			{
				throw null;
			}
		}

		public virtual IEnumerable<IAuthorizationRequirement> Requirements
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public virtual object Resource
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public virtual ClaimsPrincipal User
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthorizationHandlerContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object resource)
		{
		}

		public virtual void Fail()
		{
		}

		public virtual void Succeed(IAuthorizationRequirement requirement)
		{
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationOptions
	{
		public AuthorizationPolicy DefaultPolicy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthorizationPolicy FallbackPolicy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool InvokeHandlersAfterFailure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public void AddPolicy(string name, AuthorizationPolicy policy)
		{
		}

		public void AddPolicy(string name, Action<AuthorizationPolicyBuilder> configurePolicy)
		{
		}

		public AuthorizationPolicy GetPolicy(string name)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationPolicy.cs
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationPolicy
	{
		public IReadOnlyList<string> AuthenticationSchemes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<IAuthorizationRequirement> Requirements
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthorizationPolicy(IEnumerable<IAuthorizationRequirement> requirements, IEnumerable<string> authenticationSchemes)
		{
		}

		public static AuthorizationPolicy Combine(params AuthorizationPolicy[] policies)
		{
			throw null;
		}

		public static AuthorizationPolicy Combine(IEnumerable<AuthorizationPolicy> policies)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public static Task<AuthorizationPolicy> CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizeData> authorizeData)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationPolicyBuilder.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationPolicyBuilder
	{
		public IList<string> AuthenticationSchemes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<IAuthorizationRequirement> Requirements
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthorizationPolicyBuilder(AuthorizationPolicy policy)
		{
		}

		public AuthorizationPolicyBuilder(params string[] authenticationSchemes)
		{
		}

		public AuthorizationPolicyBuilder AddAuthenticationSchemes(params string[] schemes)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder AddRequirements(params IAuthorizationRequirement[] requirements)
		{
			throw null;
		}

		public AuthorizationPolicy Build()
		{
			throw null;
		}

		public AuthorizationPolicyBuilder Combine(AuthorizationPolicy policy)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, bool> handler)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, Task<bool>> handler)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireAuthenticatedUser()
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireClaim(string claimType)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireClaim(string claimType, IEnumerable<string> allowedValues)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireClaim(string claimType, params string[] allowedValues)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireRole(IEnumerable<string> roles)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireRole(params string[] roles)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireUserName(string userName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationResult.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationResult
	{
		public AuthorizationFailure Failure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool Succeeded
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal AuthorizationResult()
		{
		}

		public static AuthorizationResult Failed()
		{
			throw null;
		}

		public static AuthorizationResult Failed(AuthorizationFailure failure)
		{
			throw null;
		}

		public static AuthorizationResult Success()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizationServiceExtensions.cs
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public static class AuthorizationServiceExtensions
	{
		public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, AuthorizationPolicy policy)
		{
			throw null;
		}

		public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object resource, AuthorizationPolicy policy)
		{
			throw null;
		}

		public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object resource, IAuthorizationRequirement requirement)
		{
			throw null;
		}

		public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, string policyName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\AuthorizeAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authorization
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
	public class AuthorizeAttribute : Attribute, IAuthorizeData
	{
		public string AuthenticationSchemes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Policy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Roles
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthorizeAttribute()
		{
		}

		public AuthorizeAttribute(string policy)
		{
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\DefaultAuthorizationEvaluator.cs
namespace Microsoft.AspNetCore.Authorization
{
	public class DefaultAuthorizationEvaluator : IAuthorizationEvaluator
	{
		public AuthorizationResult Evaluate(AuthorizationHandlerContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\DefaultAuthorizationHandlerContextFactory.cs
using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authorization
{
	public class DefaultAuthorizationHandlerContextFactory : IAuthorizationHandlerContextFactory
	{
		public virtual AuthorizationHandlerContext CreateContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object resource)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\DefaultAuthorizationHandlerProvider.cs
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class DefaultAuthorizationHandlerProvider : IAuthorizationHandlerProvider
	{
		public DefaultAuthorizationHandlerProvider(IEnumerable<IAuthorizationHandler> handlers)
		{
		}

		public Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\DefaultAuthorizationPolicyProvider.cs
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class DefaultAuthorizationPolicyProvider : IAuthorizationPolicyProvider
	{
		public DefaultAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options)
		{
		}

		public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
		{
			throw null;
		}

		public Task<AuthorizationPolicy> GetFallbackPolicyAsync()
		{
			throw null;
		}

		public virtual Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\DefaultAuthorizationService.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class DefaultAuthorizationService : IAuthorizationService
	{
		public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IAuthorizationHandlerProvider handlers, ILogger<DefaultAuthorizationService> logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator, IOptions<AuthorizationOptions> options)
		{
		}

		[DebuggerStepThrough]
		public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\IAuthorizationEvaluator.cs
namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationEvaluator
	{
		AuthorizationResult Evaluate(AuthorizationHandlerContext context);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\IAuthorizationHandler.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationHandler
	{
		Task HandleAsync(AuthorizationHandlerContext context);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\IAuthorizationHandlerContextFactory.cs
using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationHandlerContextFactory
	{
		AuthorizationHandlerContext CreateContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object resource);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\IAuthorizationHandlerProvider.cs
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationHandlerProvider
	{
		Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync(AuthorizationHandlerContext context);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\IAuthorizationPolicyProvider.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationPolicyProvider
	{
		Task<AuthorizationPolicy> GetDefaultPolicyAsync();

		Task<AuthorizationPolicy> GetFallbackPolicyAsync();

		Task<AuthorizationPolicy> GetPolicyAsync(string policyName);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\IAuthorizationRequirement.cs
namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationRequirement
	{
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization\IAuthorizationService.cs
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationService
	{
		Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements);

		Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName);
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\AssertionRequirement.cs
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class AssertionRequirement : IAuthorizationHandler, IAuthorizationRequirement
	{
		public Func<AuthorizationHandlerContext, Task<bool>> Handler
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AssertionRequirement(Func<AuthorizationHandlerContext, bool> handler)
		{
		}

		public AssertionRequirement(Func<AuthorizationHandlerContext, Task<bool>> handler)
		{
		}

		[DebuggerStepThrough]
		public Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\ClaimsAuthorizationRequirement.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class ClaimsAuthorizationRequirement : AuthorizationHandler<ClaimsAuthorizationRequirement>, IAuthorizationRequirement
	{
		public IEnumerable<string> AllowedValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string ClaimType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ClaimsAuthorizationRequirement(string claimType, IEnumerable<string> allowedValues)
		{
		}

		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ClaimsAuthorizationRequirement requirement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\DenyAnonymousAuthorizationRequirement.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class DenyAnonymousAuthorizationRequirement : AuthorizationHandler<DenyAnonymousAuthorizationRequirement>, IAuthorizationRequirement
	{
		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DenyAnonymousAuthorizationRequirement requirement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\NameAuthorizationRequirement.cs
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class NameAuthorizationRequirement : AuthorizationHandler<NameAuthorizationRequirement>, IAuthorizationRequirement
	{
		public string RequiredName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public NameAuthorizationRequirement(string requiredName)
		{
		}

		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NameAuthorizationRequirement requirement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\OperationAuthorizationRequirement.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class OperationAuthorizationRequirement : IAuthorizationRequirement
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\PassThroughAuthorizationHandler.cs
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class PassThroughAuthorizationHandler : IAuthorizationHandler
	{
		[DebuggerStepThrough]
		public Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\RolesAuthorizationRequirement.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class RolesAuthorizationRequirement : AuthorizationHandler<RolesAuthorizationRequirement>, IAuthorizationRequirement
	{
		public IEnumerable<string> AllowedRoles
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RolesAuthorizationRequirement(IEnumerable<string> allowedRoles)
		{
		}

		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.Extensions.DependencyInjection\AuthorizationServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Authorization;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class AuthorizationServiceCollectionExtensions
	{
		public static IServiceCollection AddAuthorizationCore(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddAuthorizationCore(this IServiceCollection services, Action<AuthorizationOptions> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Authorization\AuthorizationMiddleware.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationMiddleware
	{
		public AuthorizationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Authorization.Policy\IPolicyEvaluator.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Policy
{
	public interface IPolicyEvaluator
	{
		Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context);

		Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object resource);
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Authorization.Policy\PolicyAuthorizationResult.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authorization.Policy
{
	public class PolicyAuthorizationResult
	{
		public bool Challenged
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool Forbidden
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool Succeeded
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal PolicyAuthorizationResult()
		{
		}

		public static PolicyAuthorizationResult Challenge()
		{
			throw null;
		}

		public static PolicyAuthorizationResult Forbid()
		{
			throw null;
		}

		public static PolicyAuthorizationResult Success()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Authorization.Policy\PolicyEvaluator.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Policy
{
	public class PolicyEvaluator : IPolicyEvaluator
	{
		public PolicyEvaluator(IAuthorizationService authorization)
		{
		}

		[DebuggerStepThrough]
		public virtual Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public virtual Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object resource)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Builder\AuthorizationAppBuilderExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class AuthorizationAppBuilderExtensions
	{
		public static IApplicationBuilder UseAuthorization(this IApplicationBuilder app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Builder\AuthorizationEndpointConventionBuilderExtensions.cs
using Microsoft.AspNetCore.Authorization;

namespace Microsoft.AspNetCore.Builder
{
	public static class AuthorizationEndpointConventionBuilderExtensions
	{
		public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder, params IAuthorizeData[] authorizeData) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder, params string[] policyNames) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.Extensions.DependencyInjection\PolicyServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Authorization;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class PolicyServiceCollectionExtensions
	{
		public static IServiceCollection AddAuthorization(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddAuthorization(this IServiceCollection services, Action<AuthorizationOptions> configure)
		{
			throw null;
		}

		public static IServiceCollection AddAuthorizationPolicyEvaluator(this IServiceCollection services)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\BindConverter.cs
using System;
using System.Globalization;

namespace Microsoft.AspNetCore.Components
{
	public static class BindConverter
	{
		public static bool FormatValue(bool value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTime value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTime value, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTimeOffset value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTimeOffset value, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(decimal value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(double value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(int value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(long value, CultureInfo culture = null)
		{
			throw null;
		}

		public static bool? FormatValue(bool? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTimeOffset? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTimeOffset? value, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTime? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(DateTime? value, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(decimal? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(double? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(int? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(long? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(float? value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(float value, CultureInfo culture = null)
		{
			throw null;
		}

		public static string FormatValue(string value, CultureInfo culture = null)
		{
			throw null;
		}

		public static object FormatValue<T>(T value, CultureInfo culture = null)
		{
			throw null;
		}

		public static bool TryConvertToBool(object obj, CultureInfo culture, out bool value)
		{
			throw null;
		}

		public static bool TryConvertToDateTime(object obj, CultureInfo culture, out DateTime value)
		{
			throw null;
		}

		public static bool TryConvertToDateTime(object obj, CultureInfo culture, string format, out DateTime value)
		{
			throw null;
		}

		public static bool TryConvertToDateTimeOffset(object obj, CultureInfo culture, out DateTimeOffset value)
		{
			throw null;
		}

		public static bool TryConvertToDateTimeOffset(object obj, CultureInfo culture, string format, out DateTimeOffset value)
		{
			throw null;
		}

		public static bool TryConvertToDecimal(object obj, CultureInfo culture, out decimal value)
		{
			throw null;
		}

		public static bool TryConvertToDouble(object obj, CultureInfo culture, out double value)
		{
			throw null;
		}

		public static bool TryConvertToFloat(object obj, CultureInfo culture, out float value)
		{
			throw null;
		}

		public static bool TryConvertToInt(object obj, CultureInfo culture, out int value)
		{
			throw null;
		}

		public static bool TryConvertToLong(object obj, CultureInfo culture, out long value)
		{
			throw null;
		}

		public static bool TryConvertToNullableBool(object obj, CultureInfo culture, out bool? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableDateTime(object obj, CultureInfo culture, out DateTime? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableDateTime(object obj, CultureInfo culture, string format, out DateTime? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableDateTimeOffset(object obj, CultureInfo culture, out DateTimeOffset? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableDateTimeOffset(object obj, CultureInfo culture, string format, out DateTimeOffset? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableDecimal(object obj, CultureInfo culture, out decimal? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableDouble(object obj, CultureInfo culture, out double? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableFloat(object obj, CultureInfo culture, out float? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableInt(object obj, CultureInfo culture, out int? value)
		{
			throw null;
		}

		public static bool TryConvertToNullableLong(object obj, CultureInfo culture, out long? value)
		{
			throw null;
		}

		public static bool TryConvertToString(object obj, CultureInfo culture, out string value)
		{
			throw null;
		}

		public static bool TryConvertTo<T>(object obj, CultureInfo culture, out T value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\BindElementAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = true)]
	public sealed class BindElementAttribute : Attribute
	{
		public string ChangeAttribute
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Element
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Suffix
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string ValueAttribute
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public BindElementAttribute(string element, string suffix, string valueAttribute, string changeAttribute)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\CascadingParameterAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
	public sealed class CascadingParameterAttribute : Attribute
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\CascadingParameterState.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	internal readonly struct CascadingParameterState
	{
		private readonly object _dummy;

		public string LocalValueName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ICascadingValueComponent ValueSupplier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CascadingParameterState(string localValueName, ICascadingValueComponent valueSupplier)
		{
			throw null;
		}

		public static IReadOnlyList<CascadingParameterState> FindCascadingParameters(ComponentState componentState)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\CascadingValue.cs
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public class CascadingValue<TValue> : IComponent
	{
		[Parameter]
		public RenderFragment ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public bool IsFixed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public TValue Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public void Attach(RenderHandle renderHandle)
		{
		}

		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ChangeEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public class ChangeEventArgs : EventArgs
	{
		public object Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ComponentBase.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public abstract class ComponentBase : IComponent, IHandleAfterRender, IHandleEvent
	{
		public ComponentBase()
		{
		}

		protected virtual void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected Task InvokeAsync(Action workItem)
		{
			throw null;
		}

		protected Task InvokeAsync(Func<Task> workItem)
		{
			throw null;
		}

		void IComponent.Attach(RenderHandle renderHandle)
		{
		}

		Task IHandleAfterRender.OnAfterRenderAsync()
		{
			throw null;
		}

		Task IHandleEvent.HandleEventAsync(EventCallbackWorkItem callback, object arg)
		{
			throw null;
		}

		protected virtual void OnAfterRender(bool firstRender)
		{
		}

		protected virtual Task OnAfterRenderAsync(bool firstRender)
		{
			throw null;
		}

		protected virtual void OnInitialized()
		{
		}

		protected virtual Task OnInitializedAsync()
		{
			throw null;
		}

		protected virtual void OnParametersSet()
		{
		}

		protected virtual Task OnParametersSetAsync()
		{
			throw null;
		}

		public virtual Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		protected virtual bool ShouldRender()
		{
			throw null;
		}

		protected void StateHasChanged()
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\Dispatcher.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public abstract class Dispatcher
	{
		public void AssertAccess()
		{
		}

		public abstract bool CheckAccess();

		public static Dispatcher CreateDefault()
		{
			throw null;
		}

		public abstract Task InvokeAsync(Action workItem);

		public abstract Task InvokeAsync(Func<Task> workItem);

		public abstract Task<TResult> InvokeAsync<TResult>(Func<Task<TResult>> workItem);

		public abstract Task<TResult> InvokeAsync<TResult>(Func<TResult> workItem);

		protected void OnUnhandledException(UnhandledExceptionEventArgs e)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ElementReference.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct ElementReference
	{
		private readonly object _dummy;

		public string Id
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ElementReference(string id)
		{
			throw null;
		}

		internal static ElementReference CreateWithUniqueId()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\EventCallback.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct EventCallback : IEventCallback
	{
		public static readonly EventCallback Empty;

		public static readonly EventCallbackFactory Factory;

		internal readonly MulticastDelegate Delegate;

		internal readonly IHandleEvent Receiver;

		public bool HasDelegate
		{
			get
			{
				throw null;
			}
		}

		internal bool RequiresExplicitReceiver
		{
			get
			{
				throw null;
			}
		}

		public EventCallback(IHandleEvent receiver, MulticastDelegate @delegate)
		{
			throw null;
		}

		public Task InvokeAsync(object arg)
		{
			throw null;
		}

		object IEventCallback.UnpackForRenderTree()
		{
			throw null;
		}
	}
	public readonly struct EventCallback<TValue> : IEventCallback
	{
		public static readonly EventCallback<TValue> Empty;

		internal readonly MulticastDelegate Delegate;

		internal readonly IHandleEvent Receiver;

		public bool HasDelegate
		{
			get
			{
				throw null;
			}
		}

		internal bool RequiresExplicitReceiver
		{
			get
			{
				throw null;
			}
		}

		public EventCallback(IHandleEvent receiver, MulticastDelegate @delegate)
		{
			throw null;
		}

		internal EventCallback AsUntyped()
		{
			throw null;
		}

		public Task InvokeAsync(TValue arg)
		{
			throw null;
		}

		object IEventCallback.UnpackForRenderTree()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\EventCallbackFactory.cs
using System;
using System.ComponentModel;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public sealed class EventCallbackFactory
	{
		[EditorBrowsable(EditorBrowsableState.Never)]
		public EventCallback Create(object receiver, EventCallback callback)
		{
			throw null;
		}

		public EventCallback Create(object receiver, Action callback)
		{
			throw null;
		}

		public EventCallback Create(object receiver, Action<object> callback)
		{
			throw null;
		}

		public EventCallback Create(object receiver, Func<object, Task> callback)
		{
			throw null;
		}

		public EventCallback Create(object receiver, Func<Task> callback)
		{
			throw null;
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public EventCallback<TValue> CreateInferred<TValue>(object receiver, Action<TValue> callback, TValue value)
		{
			throw null;
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public EventCallback<TValue> CreateInferred<TValue>(object receiver, Func<TValue, Task> callback, TValue value)
		{
			throw null;
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public EventCallback<TValue> Create<TValue>(object receiver, EventCallback callback)
		{
			throw null;
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public EventCallback<TValue> Create<TValue>(object receiver, EventCallback<TValue> callback)
		{
			throw null;
		}

		public EventCallback<TValue> Create<TValue>(object receiver, Action callback)
		{
			throw null;
		}

		public EventCallback<TValue> Create<TValue>(object receiver, Action<TValue> callback)
		{
			throw null;
		}

		public EventCallback<TValue> Create<TValue>(object receiver, Func<Task> callback)
		{
			throw null;
		}

		public EventCallback<TValue> Create<TValue>(object receiver, Func<TValue, Task> callback)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\EventCallbackFactoryBinderExtensions.cs
using System;
using System.Globalization;

namespace Microsoft.AspNetCore.Components
{
	public static class EventCallbackFactoryBinderExtensions
	{
		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<bool> setter, bool existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset> setter, DateTimeOffset existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset> setter, DateTimeOffset existingValue, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime> setter, DateTime existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime> setter, DateTime existingValue, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<decimal> setter, decimal existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<double> setter, double existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<int> setter, int existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<long> setter, long existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<bool?> setter, bool? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset?> setter, DateTimeOffset? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset?> setter, DateTimeOffset? existingValue, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime?> setter, DateTime? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime?> setter, DateTime? existingValue, string format, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<decimal?> setter, decimal? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<double?> setter, double? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<int?> setter, int? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<long?> setter, long? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<float?> setter, float? existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<float> setter, float existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<string> setter, string existingValue, CultureInfo culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder<T>(this EventCallbackFactory factory, object receiver, Action<T> setter, T existingValue, CultureInfo culture = null)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\EventCallbackFactoryEventArgsExtensions.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public static class EventCallbackFactoryEventArgsExtensions
	{
		public static EventCallback<ChangeEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<ChangeEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<EventArgs> Create(this EventCallbackFactory factory, object receiver, Action<EventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ChangeEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<EventArgs> Create(this EventCallbackFactory factory, object receiver, Func<EventArgs, Task> callback)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\EventCallbackWorkItem.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct EventCallbackWorkItem
	{
		private readonly object _dummy;

		public static readonly EventCallbackWorkItem Empty;

		public EventCallbackWorkItem(MulticastDelegate @delegate)
		{
			throw null;
		}

		public Task InvokeAsync(object arg)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\EventHandlerAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = true)]
	public sealed class EventHandlerAttribute : Attribute
	{
		public string AttributeName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool EnablePreventDefault
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool EnableStopPropagation
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Type EventArgsType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public EventHandlerAttribute(string attributeName, Type eventArgsType)
		{
		}

		public EventHandlerAttribute(string attributeName, Type eventArgsType, bool enableStopPropagation, bool enablePreventDefault)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ICascadingValueComponent.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;

namespace Microsoft.AspNetCore.Components
{
	internal interface ICascadingValueComponent
	{
		object CurrentValue
		{
			get;
		}

		bool CurrentValueIsFixed
		{
			get;
		}

		bool CanSupplyValue(Type valueType, string valueName);

		void Subscribe(ComponentState subscriber);

		void Unsubscribe(ComponentState subscriber);
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\IComponent.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public interface IComponent
	{
		void Attach(RenderHandle renderHandle);

		Task SetParametersAsync(ParameterView parameters);
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\IEventCallback.cs
namespace Microsoft.AspNetCore.Components
{
	internal interface IEventCallback
	{
		bool HasDelegate
		{
			get;
		}

		object UnpackForRenderTree();
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\IHandleAfterRender.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public interface IHandleAfterRender
	{
		Task OnAfterRenderAsync();
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\IHandleEvent.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public interface IHandleEvent
	{
		Task HandleEventAsync(EventCallbackWorkItem item, object arg);
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\InjectAttribute.cs
using System;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
	public sealed class InjectAttribute : Attribute
	{
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\LayoutAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
	public sealed class LayoutAttribute : Attribute
	{
		public Type LayoutType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LayoutAttribute(Type layoutType)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\LayoutComponentBase.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public abstract class LayoutComponentBase : ComponentBase
	{
		[Parameter]
		public RenderFragment Body
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\LayoutView.cs
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public class LayoutView : IComponent
	{
		[Parameter]
		public RenderFragment ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public Type Layout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public void Attach(RenderHandle renderHandle)
		{
		}

		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\LocationChangeException.cs
using System;

namespace Microsoft.AspNetCore.Components
{
	public sealed class LocationChangeException : Exception
	{
		public LocationChangeException(string message, Exception innerException)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\MarkupString.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct MarkupString
	{
		private readonly object _dummy;

		public string Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MarkupString(string value)
		{
			throw null;
		}

		public static explicit operator MarkupString(string value)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\NavigationException.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public class NavigationException : Exception
	{
		public string Location
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public NavigationException(string uri)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\NavigationManager.cs
using Microsoft.AspNetCore.Components.Routing;
using System;

namespace Microsoft.AspNetCore.Components
{
	public abstract class NavigationManager
	{
		public string BaseUri
		{
			get
			{
				throw null;
			}
			protected set
			{
			}
		}

		public string Uri
		{
			get
			{
				throw null;
			}
			protected set
			{
			}
		}

		public event EventHandler<LocationChangedEventArgs> LocationChanged
		{
			add
			{
			}
			remove
			{
			}
		}

		protected virtual void EnsureInitialized()
		{
		}

		protected void Initialize(string baseUri, string uri)
		{
		}

		public void NavigateTo(string uri, bool forceLoad = false)
		{
		}

		protected abstract void NavigateToCore(string uri, bool forceLoad);

		protected void NotifyLocationChanged(bool isInterceptedLink)
		{
		}

		public Uri ToAbsoluteUri(string relativeUri)
		{
			throw null;
		}

		public string ToBaseRelativePath(string uri)
		{
			throw null;
		}

		internal static string NormalizeBaseUri(string baseUri)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\OwningComponentBase.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public abstract class OwningComponentBase : ComponentBase, IDisposable
	{
		protected bool IsDisposed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected IServiceProvider ScopedServices
		{
			get
			{
				throw null;
			}
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		void IDisposable.Dispose()
		{
		}
	}
	public abstract class OwningComponentBase<TService> : OwningComponentBase, IDisposable
	{
		protected TService Service
		{
			get
			{
				throw null;
			}
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ParameterAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
	public sealed class ParameterAttribute : Attribute
	{
		public bool CaptureUnmatchedValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ParameterValue.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct ParameterValue
	{
		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public bool Cascading
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ParameterView.cs
using Microsoft.AspNetCore.Components.Rendering;
using Microsoft.AspNetCore.Components.RenderTree;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct ParameterView
	{
		public struct Enumerator
		{
			private object _dummy;

			private int _dummyPrimitive;

			public ParameterValue Current
			{
				get
				{
					throw null;
				}
			}

			public bool MoveNext()
			{
				throw null;
			}
		}

		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public static ParameterView Empty
		{
			get
			{
				throw null;
			}
		}

		internal ParameterViewLifetime Lifetime
		{
			get
			{
				throw null;
			}
		}

		public static ParameterView FromDictionary(IDictionary<string, object> parameters)
		{
			throw null;
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		public TValue GetValueOrDefault<TValue>(string parameterName)
		{
			throw null;
		}

		public TValue GetValueOrDefault<TValue>(string parameterName, TValue defaultValue)
		{
			throw null;
		}

		public void SetParameterProperties(object target)
		{
		}

		public IReadOnlyDictionary<string, object> ToDictionary()
		{
			throw null;
		}

		public bool TryGetValue<TValue>(string parameterName, out TValue result)
		{
			throw null;
		}

		internal ParameterView(in ParameterViewLifetime lifetime, RenderTreeFrame[] frames, int ownerIndex)
		{
			throw null;
		}

		internal void CaptureSnapshot(ArrayBuilder<RenderTreeFrame> builder)
		{
		}

		internal bool DefinitelyEquals(ParameterView oldParameters)
		{
			throw null;
		}

		internal ParameterView WithCascadingParameters(IReadOnlyList<CascadingParameterState> cascadingParameters)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\RenderFragment.cs
using Microsoft.AspNetCore.Components.Rendering;

namespace Microsoft.AspNetCore.Components
{
	public delegate void RenderFragment(RenderTreeBuilder builder);
	public delegate RenderFragment RenderFragment<TValue>(TValue value);
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\RenderHandle.cs
using Microsoft.AspNetCore.Components.RenderTree;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct RenderHandle
	{
		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public Dispatcher Dispatcher
		{
			get
			{
				throw null;
			}
		}

		public bool IsInitialized
		{
			get
			{
				throw null;
			}
		}

		public void Render(RenderFragment renderFragment)
		{
		}

		internal RenderHandle(Renderer renderer, int componentId)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\RouteAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = false)]
	public sealed class RouteAttribute : Attribute
	{
		public string Template
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteAttribute(string template)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\RouteData.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public sealed class RouteData
	{
		public Type PageType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyDictionary<string, object> RouteValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteData(Type pageType, IReadOnlyDictionary<string, object> routeValues)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\RouteView.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public class RouteView : IComponent
	{
		[Parameter]
		public Type DefaultLayout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RouteData RouteData
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public void Attach(RenderHandle renderHandle)
		{
		}

		protected virtual void Render(RenderTreeBuilder builder)
		{
		}

		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.CompilerServices\RuntimeHelpers.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.CompilerServices
{
	public static class RuntimeHelpers
	{
		public static EventCallback<T> CreateInferredEventCallback<T>(object receiver, Action<T> callback, T value)
		{
			throw null;
		}

		public static EventCallback<T> CreateInferredEventCallback<T>(object receiver, Func<T, Task> callback, T value)
		{
			throw null;
		}

		public static T TypeCheck<T>(T value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Rendering\KeyedItemInfo.cs
namespace Microsoft.AspNetCore.Components.Rendering
{
	internal readonly struct KeyedItemInfo
	{
		public readonly int OldIndex;

		public readonly int NewIndex;

		public readonly int OldSiblingIndex;

		public readonly int NewSiblingIndex;

		public KeyedItemInfo(int oldIndex, int newIndex)
		{
			throw null;
		}

		public KeyedItemInfo WithNewSiblingIndex(int newSiblingIndex)
		{
			throw null;
		}

		public KeyedItemInfo WithOldSiblingIndex(int oldSiblingIndex)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Rendering\ParameterViewLifetime.cs
namespace Microsoft.AspNetCore.Components.Rendering
{
	internal readonly struct ParameterViewLifetime
	{
		public static readonly ParameterViewLifetime Unbound;

		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public ParameterViewLifetime(RenderBatchBuilder owner)
		{
			throw null;
		}

		public void AssertNotExpired()
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Rendering\RenderQueueEntry.cs
namespace Microsoft.AspNetCore.Components.Rendering
{
	internal readonly struct RenderQueueEntry
	{
		public readonly ComponentState ComponentState;

		public readonly RenderFragment RenderFragment;

		public RenderQueueEntry(ComponentState componentState, RenderFragment renderFragment)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Rendering\RenderTreeBuilder.cs
using Microsoft.AspNetCore.Components.RenderTree;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Components.Rendering
{
	public sealed class RenderTreeBuilder : IDisposable
	{
		public void AddAttribute(int sequence, in RenderTreeFrame frame)
		{
		}

		public void AddAttribute(int sequence, string name, EventCallback value)
		{
		}

		public void AddAttribute(int sequence, string name, bool value)
		{
		}

		public void AddAttribute(int sequence, string name, MulticastDelegate value)
		{
		}

		public void AddAttribute(int sequence, string name, object value)
		{
		}

		public void AddAttribute(int sequence, string name, string value)
		{
		}

		public void AddAttribute<TArgument>(int sequence, string name, EventCallback<TArgument> value)
		{
		}

		public void AddComponentReferenceCapture(int sequence, Action<object> componentReferenceCaptureAction)
		{
		}

		public void AddContent(int sequence, MarkupString markupContent)
		{
		}

		public void AddContent(int sequence, RenderFragment fragment)
		{
		}

		public void AddContent(int sequence, object textContent)
		{
		}

		public void AddContent(int sequence, string textContent)
		{
		}

		public void AddContent<TValue>(int sequence, RenderFragment<TValue> fragment, TValue value)
		{
		}

		public void AddElementReferenceCapture(int sequence, Action<ElementReference> elementReferenceCaptureAction)
		{
		}

		public void AddMarkupContent(int sequence, string markupContent)
		{
		}

		public void AddMultipleAttributes(int sequence, IEnumerable<KeyValuePair<string, object>> attributes)
		{
		}

		public void Clear()
		{
		}

		public void CloseComponent()
		{
		}

		public void CloseElement()
		{
		}

		public void CloseRegion()
		{
		}

		public ArrayRange<RenderTreeFrame> GetFrames()
		{
			throw null;
		}

		public void OpenComponent(int sequence, Type componentType)
		{
		}

		public void OpenComponent<TComponent>(int sequence) where TComponent : IComponent
		{
		}

		public void OpenElement(int sequence, string elementName)
		{
		}

		public void OpenRegion(int sequence)
		{
		}

		public void SetKey(object value)
		{
		}

		public void SetUpdatesAttributeName(string updatesAttributeName)
		{
		}

		void IDisposable.Dispose()
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\ArrayBuilderSegment.cs
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	public readonly struct ArrayBuilderSegment<T> : IEnumerable<T>, IEnumerable
	{
		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public T[] Array
		{
			get
			{
				throw null;
			}
		}

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public T this[int index]
		{
			get
			{
				throw null;
			}
		}

		public int Offset
		{
			get
			{
				throw null;
			}
		}

		IEnumerator<T> IEnumerable<T>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\ArrayRange.cs
namespace Microsoft.AspNetCore.Components.RenderTree
{
	public readonly struct ArrayRange<T>
	{
		public readonly T[] Array;

		public readonly int Count;

		public ArrayRange(T[] array, int count)
		{
			throw null;
		}

		public ArrayRange<T> Clone()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\EventFieldInfo.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	public class EventFieldInfo
	{
		public int ComponentId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public object FieldValue
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\RenderBatch.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	public readonly struct RenderBatch
	{
		private readonly object _dummy;

		public ArrayRange<int> DisposedComponentIDs
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ArrayRange<ulong> DisposedEventHandlerIDs
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ArrayRange<RenderTreeFrame> ReferenceFrames
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ArrayRange<RenderTreeDiff> UpdatedComponents
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RenderBatch(ArrayRange<RenderTreeDiff> updatedComponents, ArrayRange<RenderTreeFrame> referenceFrames, ArrayRange<int> disposedComponentIDs, ArrayRange<ulong> disposedEventHandlerIDs)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\Renderer.cs
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	public abstract class Renderer : IDisposable
	{
		public abstract Dispatcher Dispatcher
		{
			get;
		}

		public event UnhandledExceptionEventHandler UnhandledSynchronizationException
		{
			add
			{
			}
			remove
			{
			}
		}

		public Renderer(IServiceProvider serviceProvider, ILoggerFactory loggerFactory)
		{
		}

		protected internal int AssignRootComponentId(IComponent component)
		{
			throw null;
		}

		public virtual Task DispatchEventAsync(ulong eventHandlerId, EventFieldInfo fieldInfo, EventArgs eventArgs)
		{
			throw null;
		}

		public void Dispose()
		{
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		protected ArrayRange<RenderTreeFrame> GetCurrentRenderTreeFrames(int componentId)
		{
			throw null;
		}

		protected abstract void HandleException(Exception exception);

		protected IComponent InstantiateComponent(Type componentType)
		{
			throw null;
		}

		protected virtual void ProcessPendingRender()
		{
		}

		protected Task RenderRootComponentAsync(int componentId)
		{
			throw null;
		}

		[DebuggerStepThrough]
		protected Task RenderRootComponentAsync(int componentId, ParameterView initialParameters)
		{
			throw null;
		}

		protected abstract Task UpdateDisplayAsync(in RenderBatch renderBatch);
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\RenderTreeDiff.cs
namespace Microsoft.AspNetCore.Components.RenderTree
{
	public readonly struct RenderTreeDiff
	{
		public readonly int ComponentId;

		public readonly ArrayBuilderSegment<RenderTreeEdit> Edits;

		internal RenderTreeDiff(int componentId, ArrayBuilderSegment<RenderTreeEdit> entries)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\RenderTreeEdit.cs
using System.Runtime.InteropServices;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	[StructLayout(LayoutKind.Explicit)]
	public readonly struct RenderTreeEdit
	{
		[FieldOffset(8)]
		public readonly int MoveToSiblingIndex;

		[FieldOffset(8)]
		public readonly int ReferenceFrameIndex;

		[FieldOffset(16)]
		public readonly string RemovedAttributeName;

		[FieldOffset(4)]
		public readonly int SiblingIndex;

		[FieldOffset(0)]
		public readonly RenderTreeEditType Type;

		internal static RenderTreeEdit PermutationListEnd()
		{
			throw null;
		}

		internal static RenderTreeEdit PermutationListEntry(int fromSiblingIndex, int toSiblingIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit PrependFrame(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit RemoveAttribute(int siblingIndex, string name)
		{
			throw null;
		}

		internal static RenderTreeEdit RemoveFrame(int siblingIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit SetAttribute(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit StepIn(int siblingIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit StepOut()
		{
			throw null;
		}

		internal static RenderTreeEdit UpdateMarkup(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit UpdateText(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\RenderTreeEditType.cs
namespace Microsoft.AspNetCore.Components.RenderTree
{
	public enum RenderTreeEditType
	{
		PrependFrame = 1,
		RemoveFrame,
		SetAttribute,
		RemoveAttribute,
		UpdateText,
		StepIn,
		StepOut,
		UpdateMarkup,
		PermutationListEntry,
		PermutationListEnd
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\RenderTreeFrame.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Runtime.InteropServices;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	[StructLayout(LayoutKind.Explicit, Pack = 4)]
	public readonly struct RenderTreeFrame
	{
		[FieldOffset(0)]
		public readonly int Sequence;

		[FieldOffset(4)]
		public readonly RenderTreeFrameType FrameType;

		[FieldOffset(8)]
		public readonly int ElementSubtreeLength;

		[FieldOffset(16)]
		public readonly string ElementName;

		[FieldOffset(24)]
		public readonly object ElementKey;

		[FieldOffset(16)]
		public readonly string TextContent;

		[FieldOffset(8)]
		public readonly ulong AttributeEventHandlerId;

		[FieldOffset(16)]
		public readonly string AttributeName;

		[FieldOffset(24)]
		public readonly object AttributeValue;

		[FieldOffset(32)]
		public readonly string AttributeEventUpdatesAttributeName;

		[FieldOffset(8)]
		public readonly int ComponentSubtreeLength;

		[FieldOffset(12)]
		public readonly int ComponentId;

		[FieldOffset(16)]
		public readonly Type ComponentType;

		[FieldOffset(32)]
		public readonly object ComponentKey;

		[FieldOffset(8)]
		public readonly int RegionSubtreeLength;

		[FieldOffset(16)]
		public readonly string ElementReferenceCaptureId;

		[FieldOffset(24)]
		public readonly Action<ElementReference> ElementReferenceCaptureAction;

		[FieldOffset(8)]
		public readonly int ComponentReferenceCaptureParentFrameIndex;

		[FieldOffset(16)]
		public readonly Action<object> ComponentReferenceCaptureAction;

		[FieldOffset(16)]
		public readonly string MarkupContent;

		public IComponent Component => null;

		public override string ToString()
		{
			return null;
		}

		internal static RenderTreeFrame Element(int sequence, string elementName)
		{
			throw null;
		}

		internal static RenderTreeFrame Text(int sequence, string textContent)
		{
			throw null;
		}

		internal static RenderTreeFrame Markup(int sequence, string markupContent)
		{
			throw null;
		}

		internal static RenderTreeFrame Attribute(int sequence, string name, object value)
		{
			throw null;
		}

		internal static RenderTreeFrame ChildComponent(int sequence, Type componentType)
		{
			throw null;
		}

		internal static RenderTreeFrame PlaceholderChildComponentWithSubtreeLength(int subtreeLength)
		{
			throw null;
		}

		internal static RenderTreeFrame Region(int sequence)
		{
			throw null;
		}

		internal static RenderTreeFrame ElementReferenceCapture(int sequence, Action<ElementReference> elementReferenceCaptureAction)
		{
			throw null;
		}

		internal static RenderTreeFrame ComponentReferenceCapture(int sequence, Action<object> componentReferenceCaptureAction, int parentFrameIndex)
		{
			throw null;
		}

		internal RenderTreeFrame WithElementSubtreeLength(int elementSubtreeLength)
		{
			throw null;
		}

		internal RenderTreeFrame WithComponentSubtreeLength(int componentSubtreeLength)
		{
			throw null;
		}

		internal RenderTreeFrame WithAttributeSequence(int sequence)
		{
			throw null;
		}

		internal RenderTreeFrame WithComponent(ComponentState componentState)
		{
			throw null;
		}

		internal RenderTreeFrame WithAttributeEventHandlerId(ulong eventHandlerId)
		{
			throw null;
		}

		internal RenderTreeFrame WithAttributeValue(object attributeValue)
		{
			throw null;
		}

		internal RenderTreeFrame WithAttributeEventUpdatesAttributeName(string attributeUpdatesAttributeName)
		{
			throw null;
		}

		internal RenderTreeFrame WithRegionSubtreeLength(int regionSubtreeLength)
		{
			throw null;
		}

		internal RenderTreeFrame WithElementReferenceCaptureId(string elementReferenceCaptureId)
		{
			throw null;
		}

		internal RenderTreeFrame WithElementKey(object elementKey)
		{
			throw null;
		}

		internal RenderTreeFrame WithComponentKey(object componentKey)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\RenderTreeFrameType.cs
namespace Microsoft.AspNetCore.Components.RenderTree
{
	public enum RenderTreeFrameType : short
	{
		None,
		Element,
		Text,
		Attribute,
		Component,
		Region,
		ElementReferenceCapture,
		ComponentReferenceCapture,
		Markup
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\IHostEnvironmentNavigationManager.cs
namespace Microsoft.AspNetCore.Components.Routing
{
	public interface IHostEnvironmentNavigationManager
	{
		void Initialize(string baseUri, string uri);
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\INavigationInterception.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Routing
{
	public interface INavigationInterception
	{
		Task EnableNavigationInterceptionAsync();
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\LocationChangedEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Routing
{
	public class LocationChangedEventArgs : EventArgs
	{
		public bool IsNavigationIntercepted
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Location
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LocationChangedEventArgs(string location, bool isNavigationIntercepted)
		{
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\RouteConstraint.cs
namespace Microsoft.AspNetCore.Components.Routing
{
	internal abstract class RouteConstraint
	{
		public abstract bool Match(string pathSegment, out object convertedValue);

		public static RouteConstraint Parse(string template, string segment, string constraint)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\Router.cs
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Routing
{
	public class Router : IComponent, IHandleAfterRender, IDisposable
	{
		[Parameter]
		public IEnumerable<Assembly> AdditionalAssemblies
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public Assembly AppAssembly
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment<RouteData> Found
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment NotFound
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public void Attach(RenderHandle renderHandle)
		{
		}

		public void Dispose()
		{
		}

		Task IHandleAfterRender.OnAfterRenderAsync()
		{
			throw null;
		}

		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.Extensions.Internal\HashCodeCombiner.cs
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Internal
{
	internal struct HashCodeCombiner
	{
		private long _combinedHash64;

		public int CombinedHash
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				return _combinedHash64.GetHashCode();
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private HashCodeCombiner(long seed)
		{
			_combinedHash64 = seed;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(IEnumerable e)
		{
			if (e == null)
			{
				Add(0);
				return;
			}
			int num = 0;
			foreach (object? item in e)
			{
				Add(item);
				num++;
			}
			Add(num);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static implicit operator int(HashCodeCombiner self)
		{
			return self.CombinedHash;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(int i)
		{
			_combinedHash64 = (((_combinedHash64 << 5) + _combinedHash64) ^ i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(string s)
		{
			int i = s?.GetHashCode() ?? 0;
			Add(i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(object o)
		{
			int i = o?.GetHashCode() ?? 0;
			Add(i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add<TValue>(TValue value, IEqualityComparer<TValue> comparer)
		{
			int i = (value != null) ? comparer.GetHashCode(value) : 0;
			Add(i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static HashCodeCombiner Start()
		{
			return new HashCodeCombiner(5381L);
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\AuthenticationState.cs
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public class AuthenticationState
	{
		public ClaimsPrincipal User
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticationState(ClaimsPrincipal user)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\AuthenticationStateChangedHandler.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public delegate void AuthenticationStateChangedHandler(Task<AuthenticationState> task);
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\AuthenticationStateProvider.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public abstract class AuthenticationStateProvider
	{
		public event AuthenticationStateChangedHandler AuthenticationStateChanged
		{
			add
			{
			}
			remove
			{
			}
		}

		public abstract Task<AuthenticationState> GetAuthenticationStateAsync();

		protected void NotifyAuthenticationStateChanged(Task<AuthenticationState> task)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\AuthorizeRouteView.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public sealed class AuthorizeRouteView : RouteView
	{
		[Parameter]
		public RenderFragment Authorizing
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment<AuthenticationState> NotAuthorized
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected override void Render(RenderTreeBuilder builder)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\AuthorizeView.cs
using Microsoft.AspNetCore.Authorization;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public class AuthorizeView : AuthorizeViewCore
	{
		[Parameter]
		public string Policy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public string Roles
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AuthorizeView()
		{
		}

		protected override IAuthorizeData[] GetAuthorizeData()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\AuthorizeViewCore.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public abstract class AuthorizeViewCore : ComponentBase
	{
		[Parameter]
		public RenderFragment<AuthenticationState> Authorized
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment Authorizing
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment<AuthenticationState> ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment<AuthenticationState> NotAuthorized
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public object Resource
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected abstract IAuthorizeData[] GetAuthorizeData();

		[DebuggerStepThrough]
		protected override Task OnParametersSetAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\CascadingAuthenticationState.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public class CascadingAuthenticationState : ComponentBase, IDisposable
	{
		[Parameter]
		public RenderFragment ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder __builder)
		{
		}

		protected override void OnInitialized()
		{
		}

		void IDisposable.Dispose()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\IHostEnvironmentAuthenticationStateProvider.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public interface IHostEnvironmentAuthenticationStateProvider
	{
		void SetAuthenticationState(Task<AuthenticationState> authenticationStateTask);
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\DataAnnotationsValidator.cs
namespace Microsoft.AspNetCore.Components.Forms
{
	public class DataAnnotationsValidator : ComponentBase
	{
		protected override void OnInitialized()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\EditContext.cs
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public sealed class EditContext
	{
		public object Model
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public event EventHandler<FieldChangedEventArgs> OnFieldChanged
		{
			add
			{
			}
			remove
			{
			}
		}

		public event EventHandler<ValidationRequestedEventArgs> OnValidationRequested
		{
			add
			{
			}
			remove
			{
			}
		}

		public event EventHandler<ValidationStateChangedEventArgs> OnValidationStateChanged
		{
			add
			{
			}
			remove
			{
			}
		}

		public EditContext(object model)
		{
		}

		public FieldIdentifier Field(string fieldName)
		{
			throw null;
		}

		public IEnumerable<string> GetValidationMessages()
		{
			throw null;
		}

		public IEnumerable<string> GetValidationMessages(FieldIdentifier fieldIdentifier)
		{
			throw null;
		}

		public IEnumerable<string> GetValidationMessages(Expression<Func<object>> accessor)
		{
			throw null;
		}

		public bool IsModified()
		{
			throw null;
		}

		public bool IsModified(in FieldIdentifier fieldIdentifier)
		{
			throw null;
		}

		public bool IsModified(Expression<Func<object>> accessor)
		{
			throw null;
		}

		public void MarkAsUnmodified()
		{
		}

		public void MarkAsUnmodified(in FieldIdentifier fieldIdentifier)
		{
		}

		public void NotifyFieldChanged(in FieldIdentifier fieldIdentifier)
		{
		}

		public void NotifyValidationStateChanged()
		{
		}

		public bool Validate()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\EditContextDataAnnotationsExtensions.cs
namespace Microsoft.AspNetCore.Components.Forms
{
	public static class EditContextDataAnnotationsExtensions
	{
		public static EditContext AddDataAnnotationsValidation(this EditContext editContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\FieldChangedEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public sealed class FieldChangedEventArgs : EventArgs
	{
		public FieldIdentifier FieldIdentifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FieldChangedEventArgs(in FieldIdentifier fieldIdentifier)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\FieldIdentifier.cs
using System;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public readonly struct FieldIdentifier : IEquatable<FieldIdentifier>
	{
		private readonly object _dummy;

		public string FieldName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object Model
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FieldIdentifier(object model, string fieldName)
		{
			throw null;
		}

		public static FieldIdentifier Create<TField>(Expression<Func<TField>> accessor)
		{
			throw null;
		}

		public bool Equals(FieldIdentifier otherIdentifier)
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\ValidationMessageStore.cs
using System;
using System.Collections.Generic;
using System.Linq.Expressions;

namespace Microsoft.AspNetCore.Components.Forms
{
	public sealed class ValidationMessageStore
	{
		public IEnumerable<string> this[FieldIdentifier fieldIdentifier]
		{
			get
			{
				throw null;
			}
		}

		public IEnumerable<string> this[Expression<Func<object>> accessor]
		{
			get
			{
				throw null;
			}
		}

		public ValidationMessageStore(EditContext editContext)
		{
		}

		public void Add(in FieldIdentifier fieldIdentifier, IEnumerable<string> messages)
		{
		}

		public void Add(in FieldIdentifier fieldIdentifier, string message)
		{
		}

		public void Add(Expression<Func<object>> accessor, IEnumerable<string> messages)
		{
		}

		public void Add(Expression<Func<object>> accessor, string message)
		{
		}

		public void Clear()
		{
		}

		public void Clear(in FieldIdentifier fieldIdentifier)
		{
		}

		public void Clear(Expression<Func<object>> accessor)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\ValidationRequestedEventArgs.cs
using System;

namespace Microsoft.AspNetCore.Components.Forms
{
	public sealed class ValidationRequestedEventArgs : EventArgs
	{
		public new static readonly ValidationRequestedEventArgs Empty;

		public ValidationRequestedEventArgs()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Forms\Microsoft.AspNetCore.Components.Forms\ValidationStateChangedEventArgs.cs
using System;

namespace Microsoft.AspNetCore.Components.Forms
{
	public sealed class ValidationStateChangedEventArgs : EventArgs
	{
		public new static readonly ValidationStateChangedEventArgs Empty;

		public ValidationStateChangedEventArgs()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Builder\ComponentEndpointConventionBuilder.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public sealed class ComponentEndpointConventionBuilder : IEndpointConventionBuilder, IHubEndpointConventionBuilder
	{
		internal ComponentEndpointConventionBuilder()
		{
		}

		public void Add(Action<EndpointBuilder> convention)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Builder\ComponentEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Routing;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class ComponentEndpointRouteBuilderExtensions
	{
		public static ComponentEndpointConventionBuilder MapBlazorHub(this IEndpointRouteBuilder endpoints)
		{
			throw null;
		}

		public static ComponentEndpointConventionBuilder MapBlazorHub(this IEndpointRouteBuilder endpoints, Action<HttpConnectionDispatcherOptions> configureOptions)
		{
			throw null;
		}

		public static ComponentEndpointConventionBuilder MapBlazorHub(this IEndpointRouteBuilder endpoints, string path)
		{
			throw null;
		}

		public static ComponentEndpointConventionBuilder MapBlazorHub(this IEndpointRouteBuilder endpoints, string path, Action<HttpConnectionDispatcherOptions> configureOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components\ComponentParameter.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	internal struct ComponentParameter
	{
		private object _dummy;

		public string Assembly
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string TypeName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public static (IList<ComponentParameter> parameterDefinitions, IList<object> parameterValues) FromParameterView(ParameterView parameters)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components\ServerComponent.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	internal struct ServerComponent
	{
		private object _dummy;

		private int _dummyPrimitive;

		public string AssemblyName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Guid InvocationId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<ComponentParameter> ParameterDefinitions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<object> ParameterValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int Sequence
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string TypeName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ServerComponent(int sequence, string assemblyName, string typeName, IList<ComponentParameter> parametersDefinitions, IList<object> parameterValues, Guid invocationId)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components\ServerComponentMarker.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	internal struct ServerComponentMarker
	{
		private object _dummy;

		private int _dummyPrimitive;

		public string Descriptor
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string PrerenderId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int? Sequence
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ServerComponentMarker GetEndRecord()
		{
			throw null;
		}

		public static ServerComponentMarker NonPrerendered(int sequence, string descriptor)
		{
			throw null;
		}

		public static ServerComponentMarker Prerendered(int sequence, string descriptor)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server\CircuitOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Server
{
	public sealed class CircuitOptions
	{
		public bool DetailedErrors
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int DisconnectedCircuitMaxRetained
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan DisconnectedCircuitRetentionPeriod
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan JSInteropDefaultCallTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int MaxBufferedUnacknowledgedRenderBatches
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server\RevalidatingServerAuthenticationStateProvider.cs
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Server
{
	public abstract class RevalidatingServerAuthenticationStateProvider : ServerAuthenticationStateProvider, IDisposable
	{
		protected abstract TimeSpan RevalidationInterval
		{
			get;
		}

		public RevalidatingServerAuthenticationStateProvider(ILoggerFactory loggerFactory)
		{
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		void IDisposable.Dispose()
		{
		}

		protected abstract Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken);
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server\ServerAuthenticationStateProvider.cs
using Microsoft.AspNetCore.Components.Authorization;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Server
{
	public class ServerAuthenticationStateProvider : AuthenticationStateProvider, IHostEnvironmentAuthenticationStateProvider
	{
		public override Task<AuthenticationState> GetAuthenticationStateAsync()
		{
			throw null;
		}

		public void SetAuthenticationState(Task<AuthenticationState> authenticationStateTask)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server.Circuits\Circuit.cs
namespace Microsoft.AspNetCore.Components.Server.Circuits
{
	public sealed class Circuit
	{
		public string Id
		{
			get
			{
				throw null;
			}
		}

		internal Circuit()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server.Circuits\CircuitHandler.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Server.Circuits
{
	public abstract class CircuitHandler
	{
		public virtual int Order
		{
			get
			{
				throw null;
			}
		}

		public virtual Task OnCircuitClosedAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task OnConnectionDownAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server.Circuits\CircuitId.cs
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Server.Circuits
{
	internal readonly struct CircuitId : IEquatable<CircuitId>
	{
		private readonly object _dummy;

		public string Id
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Secret
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CircuitId(string secret, string id)
		{
			throw null;
		}

		public bool Equals([AllowNull] CircuitId other)
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.Extensions.DependencyInjection\ComponentServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Components.Server;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class ComponentServiceCollectionExtensions
	{
		public static IServerSideBlazorBuilder AddServerSideBlazor(this IServiceCollection services, Action<CircuitOptions> configure = null)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.Extensions.DependencyInjection\IServerSideBlazorBuilder.cs
namespace Microsoft.Extensions.DependencyInjection
{
	public interface IServerSideBlazorBuilder
	{
		IServiceCollection Services
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.Extensions.DependencyInjection\ServerSideBlazorBuilderExtensions.cs
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.SignalR;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class ServerSideBlazorBuilderExtensions
	{
		public static IServerSideBlazorBuilder AddCircuitOptions(this IServerSideBlazorBuilder builder, Action<CircuitOptions> configure)
		{
			throw null;
		}

		public static IServerSideBlazorBuilder AddHubOptions(this IServerSideBlazorBuilder builder, Action<HubOptions> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.Extensions.Internal\ValueStopwatch.cs
using System;

namespace Microsoft.Extensions.Internal
{
	internal struct ValueStopwatch
	{
		private int _dummyPrimitive;

		public bool IsActive
		{
			get
			{
				throw null;
			}
		}

		public TimeSpan GetElapsedTime()
		{
			throw null;
		}

		public static ValueStopwatch StartNew()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components\BindInputElementAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = true)]
	public sealed class BindInputElementAttribute : Attribute
	{
		public string ChangeAttribute
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Format
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsInvariantCulture
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Suffix
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string ValueAttribute
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public BindInputElementAttribute(string type, string suffix, string valueAttribute, string changeAttribute, bool isInvariantCulture, string format)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\EditContextFieldClassExtensions.cs
using System;
using System.Linq.Expressions;

namespace Microsoft.AspNetCore.Components.Forms
{
	public static class EditContextFieldClassExtensions
	{
		public static string FieldCssClass(this EditContext editContext, in FieldIdentifier fieldIdentifier)
		{
			throw null;
		}

		public static string FieldCssClass<TField>(this EditContext editContext, Expression<Func<TField>> accessor)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\EditForm.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class EditForm : ComponentBase
	{
		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object> AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment<EditContext> ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public EditContext EditContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public object Model
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public EventCallback<EditContext> OnInvalidSubmit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public EventCallback<EditContext> OnSubmit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public EventCallback<EditContext> OnValidSubmit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public EditForm()
		{
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected override void OnParametersSet()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputBase.cs
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Forms
{
	public abstract class InputBase<TValue> : ComponentBase, IDisposable
	{
		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object> AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected string CssClass
		{
			get
			{
				throw null;
			}
		}

		protected TValue CurrentValue
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		protected string CurrentValueAsString
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		protected EditContext EditContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected FieldIdentifier FieldIdentifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public TValue Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public EventCallback<TValue> ValueChanged
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public Expression<Func<TValue>> ValueExpression
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected InputBase()
		{
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		protected virtual string FormatValueAsString(TValue value)
		{
			throw null;
		}

		public override Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		void IDisposable.Dispose()
		{
		}

		protected abstract bool TryParseValueFromString(string value, out TValue result, out string validationErrorMessage);
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputCheckbox.cs
using Microsoft.AspNetCore.Components.Rendering;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputCheckbox : InputBase<bool>
	{
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected override bool TryParseValueFromString(string value, out bool result, out string validationErrorMessage)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputDate.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputDate<TValue> : InputBase<TValue>
	{
		[Parameter]
		public string ParsingErrorMessage
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected override string FormatValueAsString(TValue value)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string value, out TValue result, out string validationErrorMessage)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputNumber.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputNumber<TValue> : InputBase<TValue>
	{
		[Parameter]
		public string ParsingErrorMessage
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected override string FormatValueAsString(TValue value)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string value, out TValue result, out string validationErrorMessage)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputSelect.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputSelect<TValue> : InputBase<TValue>
	{
		[Parameter]
		public RenderFragment ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected override bool TryParseValueFromString(string value, out TValue result, out string validationErrorMessage)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputText.cs
using Microsoft.AspNetCore.Components.Rendering;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputText : InputBase<string>
	{
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected override bool TryParseValueFromString(string value, out string result, out string validationErrorMessage)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputTextArea.cs
using Microsoft.AspNetCore.Components.Rendering;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputTextArea : InputBase<string>
	{
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected override bool TryParseValueFromString(string value, out string result, out string validationErrorMessage)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\ValidationMessage.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class ValidationMessage<TValue> : ComponentBase, IDisposable
	{
		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object> AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public Expression<Func<TValue>> For
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ValidationMessage()
		{
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		protected override void OnParametersSet()
		{
		}

		void IDisposable.Dispose()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\ValidationSummary.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class ValidationSummary : ComponentBase, IDisposable
	{
		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object> AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public object Model
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ValidationSummary()
		{
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		protected override void OnParametersSet()
		{
		}

		void IDisposable.Dispose()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.RenderTree\WebEventDescriptor.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	public sealed class WebEventDescriptor
	{
		public int BrowserRendererId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string EventArgsType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public EventFieldInfo EventFieldInfo
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ulong EventHandlerId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Routing\NavLink.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Routing
{
	public class NavLink : ComponentBase, IDisposable
	{
		[Parameter]
		public string ActiveClass
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object> AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public RenderFragment ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected string CssClass
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[Parameter]
		public NavLinkMatch Match
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
		}

		public void Dispose()
		{
		}

		protected override void OnInitialized()
		{
		}

		protected override void OnParametersSet()
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Routing\NavLinkMatch.cs
namespace Microsoft.AspNetCore.Components.Routing
{
	public enum NavLinkMatch
	{
		Prefix,
		All
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\BindAttributes.cs
namespace Microsoft.AspNetCore.Components.Web
{
	[BindElement("select", null, "value", "onchange")]
	[BindElement("textarea", null, "value", "onchange")]
	[BindInputElement("checkbox", null, "checked", "onchange", false, null)]
	[BindInputElement("date", "value", "value", "onchange", true, "yyyy-MM-dd")]
	[BindInputElement("date", null, "value", "onchange", true, "yyyy-MM-dd")]
	[BindInputElement("datetime-local", "value", "value", "onchange", true, "yyyy-MM-ddTHH:mm:ss")]
	[BindInputElement("datetime-local", null, "value", "onchange", true, "yyyy-MM-ddTHH:mm:ss")]
	[BindInputElement("month", "value", "value", "onchange", true, "yyyy-MM")]
	[BindInputElement("month", null, "value", "onchange", true, "yyyy-MM")]
	[BindInputElement("number", "value", "value", "onchange", true, null)]
	[BindInputElement("number", null, "value", "onchange", true, null)]
	[BindInputElement("text", null, "value", "onchange", false, null)]
	[BindInputElement("time", "value", "value", "onchange", true, "HH:mm:ss")]
	[BindInputElement("time", null, "value", "onchange", true, "HH:mm:ss")]
	[BindInputElement(null, "value", "value", "onchange", false, null)]
	[BindInputElement(null, null, "value", "onchange", false, null)]
	public static class BindAttributes
	{
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\ClipboardEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class ClipboardEventArgs : EventArgs
	{
		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\DataTransfer.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class DataTransfer
	{
		public string DropEffect
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string EffectAllowed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string[] Files
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public DataTransferItem[] Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string[] Types
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\DataTransferItem.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class DataTransferItem
	{
		public string Kind
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\DragEventArgs.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class DragEventArgs : MouseEventArgs
	{
		public DataTransfer DataTransfer
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\ErrorEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class ErrorEventArgs : EventArgs
	{
		public int Colno
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Filename
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int Lineno
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Message
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\EventHandlers.cs
using System;

namespace Microsoft.AspNetCore.Components.Web
{
	[EventHandler("onabort", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onactivate", typeof(EventArgs), true, true)]
	[EventHandler("onbeforeactivate", typeof(EventArgs), true, true)]
	[EventHandler("onbeforecopy", typeof(EventArgs), true, true)]
	[EventHandler("onbeforecut", typeof(EventArgs), true, true)]
	[EventHandler("onbeforedeactivate", typeof(EventArgs), true, true)]
	[EventHandler("onbeforepaste", typeof(EventArgs), true, true)]
	[EventHandler("onblur", typeof(FocusEventArgs), true, true)]
	[EventHandler("oncanplay", typeof(EventArgs), true, true)]
	[EventHandler("oncanplaythrough", typeof(EventArgs), true, true)]
	[EventHandler("onchange", typeof(ChangeEventArgs), true, true)]
	[EventHandler("onclick", typeof(MouseEventArgs), true, true)]
	[EventHandler("oncontextmenu", typeof(MouseEventArgs), true, true)]
	[EventHandler("oncopy", typeof(ClipboardEventArgs), true, true)]
	[EventHandler("oncuechange", typeof(EventArgs), true, true)]
	[EventHandler("oncut", typeof(ClipboardEventArgs), true, true)]
	[EventHandler("ondblclick", typeof(MouseEventArgs), true, true)]
	[EventHandler("ondeactivate", typeof(EventArgs), true, true)]
	[EventHandler("ondrag", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragend", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragenter", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragleave", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragover", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragstart", typeof(DragEventArgs), true, true)]
	[EventHandler("ondrop", typeof(DragEventArgs), true, true)]
	[EventHandler("ondurationchange", typeof(EventArgs), true, true)]
	[EventHandler("onemptied", typeof(EventArgs), true, true)]
	[EventHandler("onended", typeof(EventArgs), true, true)]
	[EventHandler("onerror", typeof(ErrorEventArgs), true, true)]
	[EventHandler("onfocus", typeof(FocusEventArgs), true, true)]
	[EventHandler("onfocusin", typeof(FocusEventArgs), true, true)]
	[EventHandler("onfocusout", typeof(FocusEventArgs), true, true)]
	[EventHandler("onfullscreenchange", typeof(EventArgs), true, true)]
	[EventHandler("onfullscreenerror", typeof(EventArgs), true, true)]
	[EventHandler("ongotpointercapture", typeof(PointerEventArgs), true, true)]
	[EventHandler("oninput", typeof(ChangeEventArgs), true, true)]
	[EventHandler("oninvalid", typeof(EventArgs), true, true)]
	[EventHandler("onkeydown", typeof(KeyboardEventArgs), true, true)]
	[EventHandler("onkeypress", typeof(KeyboardEventArgs), true, true)]
	[EventHandler("onkeyup", typeof(KeyboardEventArgs), true, true)]
	[EventHandler("onload", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onloadeddata", typeof(EventArgs), true, true)]
	[EventHandler("onloadedmetadata", typeof(EventArgs), true, true)]
	[EventHandler("onloadend", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onloadstart", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onlostpointercapture", typeof(PointerEventArgs), true, true)]
	[EventHandler("onmousedown", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmousemove", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmouseout", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmouseover", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmouseup", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmousewheel", typeof(WheelEventArgs), true, true)]
	[EventHandler("onpaste", typeof(ClipboardEventArgs), true, true)]
	[EventHandler("onpause", typeof(EventArgs), true, true)]
	[EventHandler("onplay", typeof(EventArgs), true, true)]
	[EventHandler("onplaying", typeof(EventArgs), true, true)]
	[EventHandler("onpointercancel", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerdown", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerenter", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerleave", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerlockchange", typeof(EventArgs), true, true)]
	[EventHandler("onpointerlockerror", typeof(EventArgs), true, true)]
	[EventHandler("onpointermove", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerout", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerover", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerup", typeof(PointerEventArgs), true, true)]
	[EventHandler("onprogress", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onratechange", typeof(EventArgs), true, true)]
	[EventHandler("onreadystatechange", typeof(EventArgs), true, true)]
	[EventHandler("onreset", typeof(EventArgs), true, true)]
	[EventHandler("onscroll", typeof(EventArgs), true, true)]
	[EventHandler("onseeked", typeof(EventArgs), true, true)]
	[EventHandler("onseeking", typeof(EventArgs), true, true)]
	[EventHandler("onselect", typeof(EventArgs), true, true)]
	[EventHandler("onselectionchange", typeof(EventArgs), true, true)]
	[EventHandler("onselectstart", typeof(EventArgs), true, true)]
	[EventHandler("onstalled", typeof(EventArgs), true, true)]
	[EventHandler("onstop", typeof(EventArgs), true, true)]
	[EventHandler("onsubmit", typeof(EventArgs), true, true)]
	[EventHandler("onsuspend", typeof(EventArgs), true, true)]
	[EventHandler("ontimeout", typeof(ProgressEventArgs), true, true)]
	[EventHandler("ontimeupdate", typeof(EventArgs), true, true)]
	[EventHandler("ontouchcancel", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchend", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchenter", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchleave", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchmove", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchstart", typeof(TouchEventArgs), true, true)]
	[EventHandler("onvolumechange", typeof(EventArgs), true, true)]
	[EventHandler("onwaiting", typeof(EventArgs), true, true)]
	[EventHandler("onwheel", typeof(WheelEventArgs), true, true)]
	public static class EventHandlers
	{
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\FocusEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class FocusEventArgs : EventArgs
	{
		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\KeyboardEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class KeyboardEventArgs : EventArgs
	{
		public bool AltKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Code
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool CtrlKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Key
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public float Location
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool MetaKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool Repeat
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool ShiftKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\MouseEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class MouseEventArgs : EventArgs
	{
		public bool AltKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Button
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Buttons
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double ClientX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double ClientY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool CtrlKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Detail
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool MetaKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double ScreenX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double ScreenY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool ShiftKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\PointerEventArgs.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class PointerEventArgs : MouseEventArgs
	{
		public float Height
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool IsPrimary
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long PointerId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string PointerType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public float Pressure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public float TiltX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public float TiltY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public float Width
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\ProgressEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class ProgressEventArgs : EventArgs
	{
		public bool LengthComputable
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Loaded
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Total
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\TouchEventArgs.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class TouchEventArgs : EventArgs
	{
		public bool AltKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TouchPoint[] ChangedTouches
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool CtrlKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Detail
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool MetaKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool ShiftKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TouchPoint[] TargetTouches
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TouchPoint[] Touches
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\TouchPoint.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class TouchPoint
	{
		public double ClientX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double ClientY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Identifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double PageX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double PageY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double ScreenX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double ScreenY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\WebEventCallbackFactoryEventArgsExtensions.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Web
{
	public static class WebEventCallbackFactoryEventArgsExtensions
	{
		public static EventCallback<ClipboardEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<ClipboardEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<DragEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<DragEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<ErrorEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<ErrorEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<FocusEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<FocusEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<KeyboardEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<KeyboardEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<MouseEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<MouseEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<PointerEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<PointerEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<ProgressEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<ProgressEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<TouchEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<TouchEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<WheelEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<WheelEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<ClipboardEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ClipboardEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<DragEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<DragEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<ErrorEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ErrorEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<FocusEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<FocusEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<KeyboardEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<KeyboardEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<MouseEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<MouseEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<PointerEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<PointerEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<ProgressEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ProgressEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<TouchEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<TouchEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<WheelEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<WheelEventArgs, Task> callback)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\WebRenderTreeBuilderExtensions.cs
using Microsoft.AspNetCore.Components.Rendering;

namespace Microsoft.AspNetCore.Components.Web
{
	public static class WebRenderTreeBuilderExtensions
	{
		public static void AddEventPreventDefaultAttribute(this RenderTreeBuilder builder, int sequence, string eventName, bool value)
		{
		}

		public static void AddEventStopPropagationAttribute(this RenderTreeBuilder builder, int sequence, string eventName, bool value)
		{
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\WheelEventArgs.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class WheelEventArgs : MouseEventArgs
	{
		public long DeltaMode
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double DeltaX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double DeltaY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public double DeltaZ
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\AddressInUseException.cs
using System;

namespace Microsoft.AspNetCore.Connections
{
	public class AddressInUseException : InvalidOperationException
	{
		public AddressInUseException(string message)
		{
		}

		public AddressInUseException(string message, Exception inner)
		{
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionAbortedException.cs
using System;

namespace Microsoft.AspNetCore.Connections
{
	public class ConnectionAbortedException : OperationCanceledException
	{
		public ConnectionAbortedException()
		{
		}

		public ConnectionAbortedException(string message)
		{
		}

		public ConnectionAbortedException(string message, Exception inner)
		{
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionBuilder.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Connections
{
	public class ConnectionBuilder : IConnectionBuilder
	{
		public IServiceProvider ApplicationServices
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ConnectionBuilder(IServiceProvider applicationServices)
		{
		}

		public ConnectionDelegate Build()
		{
			throw null;
		}

		public IConnectionBuilder Use(Func<ConnectionDelegate, ConnectionDelegate> middleware)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionBuilderExtensions.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public static class ConnectionBuilderExtensions
	{
		public static IConnectionBuilder Run(this IConnectionBuilder connectionBuilder, Func<ConnectionContext, Task> middleware)
		{
			throw null;
		}

		public static IConnectionBuilder Use(this IConnectionBuilder connectionBuilder, Func<ConnectionContext, Func<Task>, Task> middleware)
		{
			throw null;
		}

		public static IConnectionBuilder UseConnectionHandler<TConnectionHandler>(this IConnectionBuilder connectionBuilder) where TConnectionHandler : ConnectionHandler
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionContext.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public abstract class ConnectionContext : IAsyncDisposable
	{
		public virtual CancellationToken ConnectionClosed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public abstract string ConnectionId
		{
			get;
			set;
		}

		public abstract IFeatureCollection Features
		{
			get;
		}

		public abstract IDictionary<object, object> Items
		{
			get;
			set;
		}

		public virtual EndPoint LocalEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual EndPoint RemoteEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public abstract IDuplexPipe Transport
		{
			get;
			set;
		}

		public virtual void Abort()
		{
		}

		public virtual void Abort(ConnectionAbortedException abortReason)
		{
		}

		public virtual ValueTask DisposeAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionDelegate.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public delegate Task ConnectionDelegate(ConnectionContext connection);
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionHandler.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public abstract class ConnectionHandler
	{
		public abstract Task OnConnectedAsync(ConnectionContext connection);
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionItems.cs
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Connections
{
	public class ConnectionItems : ICollection<KeyValuePair<object, object>>, IEnumerable<KeyValuePair<object, object>>, IEnumerable, IDictionary<object, object>
	{
		public IDictionary<object, object> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		int ICollection<KeyValuePair<object, object>>.Count
		{
			get
			{
				throw null;
			}
		}

		bool ICollection<KeyValuePair<object, object>>.IsReadOnly
		{
			get
			{
				throw null;
			}
		}

		object IDictionary<object, object>.this[object key]
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		ICollection<object> IDictionary<object, object>.Keys
		{
			get
			{
				throw null;
			}
		}

		ICollection<object> IDictionary<object, object>.Values
		{
			get
			{
				throw null;
			}
		}

		public ConnectionItems()
		{
		}

		public ConnectionItems(IDictionary<object, object> items)
		{
		}

		void ICollection<KeyValuePair<object, object>>.Add(KeyValuePair<object, object> item)
		{
		}

		void ICollection<KeyValuePair<object, object>>.Clear()
		{
		}

		bool ICollection<KeyValuePair<object, object>>.Contains(KeyValuePair<object, object> item)
		{
			throw null;
		}

		void ICollection<KeyValuePair<object, object>>.CopyTo(KeyValuePair<object, object>[] array, int arrayIndex)
		{
		}

		bool ICollection<KeyValuePair<object, object>>.Remove(KeyValuePair<object, object> item)
		{
			throw null;
		}

		void IDictionary<object, object>.Add(object key, object value)
		{
		}

		bool IDictionary<object, object>.ContainsKey(object key)
		{
			throw null;
		}

		bool IDictionary<object, object>.Remove(object key)
		{
			throw null;
		}

		bool IDictionary<object, object>.TryGetValue(object key, out object value)
		{
			throw null;
		}

		IEnumerator<KeyValuePair<object, object>> IEnumerable<KeyValuePair<object, object>>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionResetException.cs
using System;
using System.IO;

namespace Microsoft.AspNetCore.Connections
{
	public class ConnectionResetException : IOException
	{
		public ConnectionResetException(string message)
		{
		}

		public ConnectionResetException(string message, Exception inner)
		{
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\DefaultConnectionContext.cs
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public class DefaultConnectionContext : ConnectionContext, IConnectionEndPointFeature, IConnectionIdFeature, IConnectionItemsFeature, IConnectionLifetimeFeature, IConnectionTransportFeature, IConnectionUserFeature
	{
		public IDuplexPipe Application
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override CancellationToken ConnectionClosed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override string ConnectionId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override IFeatureCollection Features
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public override IDictionary<object, object> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override EndPoint LocalEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override EndPoint RemoteEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override IDuplexPipe Transport
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ClaimsPrincipal User
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public DefaultConnectionContext()
		{
		}

		public DefaultConnectionContext(string id)
		{
		}

		public DefaultConnectionContext(string id, IDuplexPipe transport, IDuplexPipe application)
		{
		}

		public override void Abort(ConnectionAbortedException abortReason)
		{
		}

		public override ValueTask DisposeAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\FileHandleEndPoint.cs
using System.Net;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Connections
{
	public class FileHandleEndPoint : EndPoint
	{
		public ulong FileHandle
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FileHandleType FileHandleType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FileHandleEndPoint(ulong fileHandle, FileHandleType fileHandleType)
		{
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\FileHandleType.cs
namespace Microsoft.AspNetCore.Connections
{
	public enum FileHandleType
	{
		Auto,
		Tcp,
		Pipe
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IConnectionBuilder.cs
using System;

namespace Microsoft.AspNetCore.Connections
{
	public interface IConnectionBuilder
	{
		IServiceProvider ApplicationServices
		{
			get;
		}

		ConnectionDelegate Build();

		IConnectionBuilder Use(Func<ConnectionDelegate, ConnectionDelegate> middleware);
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IConnectionFactory.cs
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public interface IConnectionFactory
	{
		ValueTask<ConnectionContext> ConnectAsync(EndPoint endpoint, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IConnectionListener.cs
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public interface IConnectionListener : IAsyncDisposable
	{
		EndPoint EndPoint
		{
			get;
		}

		ValueTask<ConnectionContext> AcceptAsync(CancellationToken cancellationToken = default(CancellationToken));

		ValueTask UnbindAsync(CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IConnectionListenerFactory.cs
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public interface IConnectionListenerFactory
	{
		ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\TransferFormat.cs
using System;

namespace Microsoft.AspNetCore.Connections
{
	[Flags]
	public enum TransferFormat
	{
		Binary = 0x1,
		Text = 0x2
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\UriEndPoint.cs
using System;
using System.Net;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Connections
{
	public class UriEndPoint : EndPoint
	{
		public Uri Uri
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public UriEndPoint(Uri uri)
		{
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionCompleteFeature.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionCompleteFeature
	{
		void OnCompleted(Func<object, Task> callback, object state);
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionEndPointFeature.cs
using System.Net;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionEndPointFeature
	{
		EndPoint LocalEndPoint
		{
			get;
			set;
		}

		EndPoint RemoteEndPoint
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionHeartbeatFeature.cs
using System;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionHeartbeatFeature
	{
		void OnHeartbeat(Action<object> action, object state);
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionIdFeature.cs
namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionIdFeature
	{
		string ConnectionId
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionInherentKeepAliveFeature.cs
namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionInherentKeepAliveFeature
	{
		bool HasInherentKeepAlive
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionItemsFeature.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionItemsFeature
	{
		IDictionary<object, object> Items
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionLifetimeFeature.cs
using System.Threading;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionLifetimeFeature
	{
		CancellationToken ConnectionClosed
		{
			get;
			set;
		}

		void Abort();
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionLifetimeNotificationFeature.cs
using System.Threading;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionLifetimeNotificationFeature
	{
		CancellationToken ConnectionClosedRequested
		{
			get;
			set;
		}

		void RequestClose();
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionTransportFeature.cs
using System.IO.Pipelines;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionTransportFeature
	{
		IDuplexPipe Transport
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IConnectionUserFeature.cs
using System.Security.Claims;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IConnectionUserFeature
	{
		ClaimsPrincipal User
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IMemoryPoolFeature.cs
using System.Buffers;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IMemoryPoolFeature
	{
		MemoryPool<byte> MemoryPool
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\ITlsHandshakeFeature.cs
using System.Security.Authentication;

namespace Microsoft.AspNetCore.Connections.Features
{
	public interface ITlsHandshakeFeature
	{
		CipherAlgorithmType CipherAlgorithm
		{
			get;
		}

		int CipherStrength
		{
			get;
		}

		HashAlgorithmType HashAlgorithm
		{
			get;
		}

		int HashStrength
		{
			get;
		}

		ExchangeAlgorithmType KeyExchangeAlgorithm
		{
			get;
		}

		int KeyExchangeStrength
		{
			get;
		}

		SslProtocols Protocol
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\ITransferFormatFeature.cs
namespace Microsoft.AspNetCore.Connections.Features
{
	public interface ITransferFormatFeature
	{
		TransferFormat ActiveFormat
		{
			get;
			set;
		}

		TransferFormat SupportedFormats
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.Extensions.Internal\ObjectFactory.cs
using System;

namespace Microsoft.Extensions.Internal
{
	internal delegate object ObjectFactory(IServiceProvider serviceProvider, object[] arguments);
}


// Microsoft.AspNetCore.CookiePolicy\Microsoft.AspNetCore.Builder\CookiePolicyAppBuilderExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class CookiePolicyAppBuilderExtensions
	{
		public static IApplicationBuilder UseCookiePolicy(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseCookiePolicy(this IApplicationBuilder app, CookiePolicyOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.CookiePolicy\Microsoft.AspNetCore.Builder\CookiePolicyOptions.cs
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class CookiePolicyOptions
	{
		public Func<HttpContext, bool> CheckConsentNeeded
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookieBuilder ConsentCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public HttpOnlyPolicy HttpOnly
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public SameSiteMode MinimumSameSitePolicy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Action<AppendCookieContext> OnAppendCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Action<DeleteCookieContext> OnDeleteCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookieSecurePolicy Secure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.CookiePolicy\Microsoft.AspNetCore.CookiePolicy\AppendCookieContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.CookiePolicy
{
	public class AppendCookieContext
	{
		public HttpContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string CookieName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookieOptions CookieOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string CookieValue
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool HasConsent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsConsentNeeded
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IssueCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public AppendCookieContext(HttpContext context, CookieOptions options, string name, string value)
		{
		}
	}
}


// Microsoft.AspNetCore.CookiePolicy\Microsoft.AspNetCore.CookiePolicy\CookiePolicyMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.CookiePolicy
{
	public class CookiePolicyMiddleware
	{
		public CookiePolicyOptions Options
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookiePolicyMiddleware(RequestDelegate next, IOptions<CookiePolicyOptions> options)
		{
		}

		public CookiePolicyMiddleware(RequestDelegate next, IOptions<CookiePolicyOptions> options, ILoggerFactory factory)
		{
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.CookiePolicy\Microsoft.AspNetCore.CookiePolicy\DeleteCookieContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.CookiePolicy
{
	public class DeleteCookieContext
	{
		public HttpContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string CookieName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookieOptions CookieOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool HasConsent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsConsentNeeded
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IssueCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public DeleteCookieContext(HttpContext context, CookieOptions options, string name)
		{
		}
	}
}


// Microsoft.AspNetCore.CookiePolicy\Microsoft.AspNetCore.CookiePolicy\HttpOnlyPolicy.cs
namespace Microsoft.AspNetCore.CookiePolicy
{
	public enum HttpOnlyPolicy
	{
		None,
		Always
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Builder\CorsEndpointConventionBuilderExtensions.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class CorsEndpointConventionBuilderExtensions
	{
		public static TBuilder RequireCors<TBuilder>(this TBuilder builder, Action<CorsPolicyBuilder> configurePolicy) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder RequireCors<TBuilder>(this TBuilder builder, string policyName) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Builder\CorsMiddlewareExtensions.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class CorsMiddlewareExtensions
	{
		public static IApplicationBuilder UseCors(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseCors(this IApplicationBuilder app, Action<CorsPolicyBuilder> configurePolicy)
		{
			throw null;
		}

		public static IApplicationBuilder UseCors(this IApplicationBuilder app, string policyName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors\CorsPolicyMetadata.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Cors
{
	public class CorsPolicyMetadata : ICorsMetadata, ICorsPolicyMetadata
	{
		public CorsPolicy Policy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CorsPolicyMetadata(CorsPolicy policy)
		{
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors\DisableCorsAttribute.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;

namespace Microsoft.AspNetCore.Cors
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
	public class DisableCorsAttribute : Attribute, ICorsMetadata, IDisableCorsAttribute
	{
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors\EnableCorsAttribute.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Cors
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
	public class EnableCorsAttribute : Attribute, ICorsMetadata, IEnableCorsAttribute
	{
		public string PolicyName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public EnableCorsAttribute()
		{
		}

		public EnableCorsAttribute(string policyName)
		{
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsConstants.cs
namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public static class CorsConstants
	{
		public static readonly string AccessControlAllowCredentials;

		public static readonly string AccessControlAllowHeaders;

		public static readonly string AccessControlAllowMethods;

		public static readonly string AccessControlAllowOrigin;

		public static readonly string AccessControlExposeHeaders;

		public static readonly string AccessControlMaxAge;

		public static readonly string AccessControlRequestHeaders;

		public static readonly string AccessControlRequestMethod;

		public static readonly string AnyOrigin;

		public static readonly string Origin;

		public static readonly string PreflightHttpMethod;
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsMiddleware.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class CorsMiddleware
	{
		public CorsMiddleware(RequestDelegate next, ICorsService corsService, CorsPolicy policy, ILoggerFactory loggerFactory)
		{
		}

		public CorsMiddleware(RequestDelegate next, ICorsService corsService, ILoggerFactory loggerFactory)
		{
		}

		public CorsMiddleware(RequestDelegate next, ICorsService corsService, ILoggerFactory loggerFactory, string policyName)
		{
		}

		public Task Invoke(HttpContext context, ICorsPolicyProvider corsPolicyProvider)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsOptions.cs
using System;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class CorsOptions
	{
		public string DefaultPolicyName
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public void AddDefaultPolicy(CorsPolicy policy)
		{
		}

		public void AddDefaultPolicy(Action<CorsPolicyBuilder> configurePolicy)
		{
		}

		public void AddPolicy(string name, CorsPolicy policy)
		{
		}

		public void AddPolicy(string name, Action<CorsPolicyBuilder> configurePolicy)
		{
		}

		public CorsPolicy GetPolicy(string name)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsPolicy.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class CorsPolicy
	{
		public bool AllowAnyHeader
		{
			get
			{
				throw null;
			}
		}

		public bool AllowAnyMethod
		{
			get
			{
				throw null;
			}
		}

		public bool AllowAnyOrigin
		{
			get
			{
				throw null;
			}
		}

		public IList<string> ExposedHeaders
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<string> Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Func<string, bool> IsOriginAllowed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<string> Methods
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<string> Origins
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TimeSpan? PreflightMaxAge
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public bool SupportsCredentials
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CorsPolicy()
		{
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsPolicyBuilder.cs
using System;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class CorsPolicyBuilder
	{
		public CorsPolicyBuilder(CorsPolicy policy)
		{
		}

		public CorsPolicyBuilder(params string[] origins)
		{
		}

		public CorsPolicyBuilder AllowAnyHeader()
		{
			throw null;
		}

		public CorsPolicyBuilder AllowAnyMethod()
		{
			throw null;
		}

		public CorsPolicyBuilder AllowAnyOrigin()
		{
			throw null;
		}

		public CorsPolicyBuilder AllowCredentials()
		{
			throw null;
		}

		public CorsPolicy Build()
		{
			throw null;
		}

		public CorsPolicyBuilder DisallowCredentials()
		{
			throw null;
		}

		public CorsPolicyBuilder SetIsOriginAllowed(Func<string, bool> isOriginAllowed)
		{
			throw null;
		}

		public CorsPolicyBuilder SetIsOriginAllowedToAllowWildcardSubdomains()
		{
			throw null;
		}

		public CorsPolicyBuilder SetPreflightMaxAge(TimeSpan preflightMaxAge)
		{
			throw null;
		}

		public CorsPolicyBuilder WithExposedHeaders(params string[] exposedHeaders)
		{
			throw null;
		}

		public CorsPolicyBuilder WithHeaders(params string[] headers)
		{
			throw null;
		}

		public CorsPolicyBuilder WithMethods(params string[] methods)
		{
			throw null;
		}

		public CorsPolicyBuilder WithOrigins(params string[] origins)
		{
			throw null;
		}

		internal static string GetNormalizedOrigin(string origin)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsResult.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class CorsResult
	{
		public IList<string> AllowedExposedHeaders
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<string> AllowedHeaders
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<string> AllowedMethods
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string AllowedOrigin
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool IsOriginAllowed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool IsPreflightRequest
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan? PreflightMaxAge
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public bool SupportsCredentials
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool VaryByOrigin
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsService.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class CorsService : ICorsService
	{
		public CorsService(IOptions<CorsOptions> options, ILoggerFactory loggerFactory)
		{
		}

		public virtual void ApplyResult(CorsResult result, HttpResponse response)
		{
		}

		public CorsResult EvaluatePolicy(HttpContext context, CorsPolicy policy)
		{
			throw null;
		}

		public CorsResult EvaluatePolicy(HttpContext context, string policyName)
		{
			throw null;
		}

		public virtual void EvaluatePreflightRequest(HttpContext context, CorsPolicy policy, CorsResult result)
		{
		}

		public virtual void EvaluateRequest(HttpContext context, CorsPolicy policy, CorsResult result)
		{
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\DefaultCorsPolicyProvider.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class DefaultCorsPolicyProvider : ICorsPolicyProvider
	{
		public DefaultCorsPolicyProvider(IOptions<CorsOptions> options)
		{
		}

		public Task<CorsPolicy> GetPolicyAsync(HttpContext context, string policyName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\ICorsPolicyMetadata.cs
namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public interface ICorsPolicyMetadata : ICorsMetadata
	{
		CorsPolicy Policy
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\ICorsPolicyProvider.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public interface ICorsPolicyProvider
	{
		Task<CorsPolicy> GetPolicyAsync(HttpContext context, string policyName);
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\ICorsService.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public interface ICorsService
	{
		void ApplyResult(CorsResult result, HttpResponse response);

		CorsResult EvaluatePolicy(HttpContext context, CorsPolicy policy);
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\IDisableCorsAttribute.cs
namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public interface IDisableCorsAttribute : ICorsMetadata
	{
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\IEnableCorsAttribute.cs
namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public interface IEnableCorsAttribute : ICorsMetadata
	{
		string PolicyName
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.Extensions.DependencyInjection\CorsServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class CorsServiceCollectionExtensions
	{
		public static IServiceCollection AddCors(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddCors(this IServiceCollection services, Action<CorsOptions> setupAction)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography\DATA_BLOB.cs
namespace Microsoft.AspNetCore.Cryptography
{
	internal struct DATA_BLOB
	{
		public uint cbData;

		public unsafe byte* pbData;
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\BCryptBuffer.cs
using System;

namespace Microsoft.AspNetCore.Cryptography.Cng
{
	internal struct BCryptBuffer
	{
		public uint cbBuffer;

		public BCryptKeyDerivationBufferType BufferType;

		public IntPtr pvBuffer;
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\BCryptBufferDesc.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Cryptography.Cng
{
	internal struct BCryptBufferDesc
	{
		public uint ulVersion;

		public uint cBuffers;

		public unsafe BCryptBuffer* pBuffers;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Initialize(ref BCryptBufferDesc bufferDesc)
		{
		}
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\BCryptEncryptFlags.cs
using System;

namespace Microsoft.AspNetCore.Cryptography.Cng
{
	[Flags]
	internal enum BCryptEncryptFlags
	{
		BCRYPT_BLOCK_PADDING = 0x1
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\BCryptGenRandomFlags.cs
using System;

namespace Microsoft.AspNetCore.Cryptography.Cng
{
	[Flags]
	internal enum BCryptGenRandomFlags
	{
		BCRYPT_RNG_USE_ENTROPY_IN_BUFFER = 0x1,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x2
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\BCryptKeyDerivationBufferType.cs
namespace Microsoft.AspNetCore.Cryptography.Cng
{
	internal enum BCryptKeyDerivationBufferType
	{
		KDF_HASH_ALGORITHM,
		KDF_SECRET_PREPEND,
		KDF_SECRET_APPEND,
		KDF_HMAC_KEY,
		KDF_TLS_PRF_LABEL,
		KDF_TLS_PRF_SEED,
		KDF_SECRET_HANDLE,
		KDF_TLS_PRF_PROTOCOL,
		KDF_ALGORITHMID,
		KDF_PARTYUINFO,
		KDF_PARTYVINFO,
		KDF_SUPPPUBINFO,
		KDF_SUPPPRIVINFO,
		KDF_LABEL,
		KDF_CONTEXT,
		KDF_SALT,
		KDF_ITERATION_COUNT
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.cs
namespace Microsoft.AspNetCore.Cryptography.Cng
{
	internal struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
	{
		public uint cbSize;

		public uint dwInfoVersion;

		public unsafe byte* pbNonce;

		public uint cbNonce;

		public unsafe byte* pbAuthData;

		public uint cbAuthData;

		public unsafe byte* pbTag;

		public uint cbTag;

		public unsafe byte* pbMacContext;

		public uint cbMacContext;

		public uint cbAAD;

		public ulong cbData;

		public uint dwFlags;

		public static void Init(out BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\BCRYPT_KEY_LENGTHS_STRUCT.cs
namespace Microsoft.AspNetCore.Cryptography.Cng
{
	internal struct BCRYPT_KEY_LENGTHS_STRUCT
	{
		internal uint dwMinLength;

		internal uint dwMaxLength;

		internal uint dwIncrement;

		public void EnsureValidKeyLength(uint keyLengthInBits)
		{
		}
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.Cng\NCryptEncryptFlags.cs
using System;

namespace Microsoft.AspNetCore.Cryptography.Cng
{
	[Flags]
	internal enum NCryptEncryptFlags
	{
		NCRYPT_NO_PADDING_FLAG = 0x1,
		NCRYPT_PAD_PKCS1_FLAG = 0x2,
		NCRYPT_PAD_OAEP_FLAG = 0x4,
		NCRYPT_PAD_PSS_FLAG = 0x8,
		NCRYPT_SILENT_FLAG = 0x40
	}
}


// Microsoft.AspNetCore.Cryptography.Internal\Microsoft.AspNetCore.Cryptography.SafeHandles\BCryptHandle.cs
using Microsoft.Win32.SafeHandles;

namespace Microsoft.AspNetCore.Cryptography.SafeHandles
{
	internal abstract class BCryptHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		protected BCryptHandle()
			: base(ownsHandle: false)
		{
		}

		protected unsafe uint GetProperty(string pszProperty, void* pbOutput, uint cbOutput)
		{
			throw null;
		}

		protected unsafe void SetProperty(string pszProperty, void* pbInput, uint cbInput)
		{
		}
	}
}


// Microsoft.AspNetCore.Cryptography.KeyDerivation\Microsoft.AspNetCore.Cryptography.KeyDerivation\KeyDerivation.cs
namespace Microsoft.AspNetCore.Cryptography.KeyDerivation
{
	public static class KeyDerivation
	{
		public static byte[] Pbkdf2(string password, byte[] salt, KeyDerivationPrf prf, int iterationCount, int numBytesRequested)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cryptography.KeyDerivation\Microsoft.AspNetCore.Cryptography.KeyDerivation\KeyDerivationPrf.cs
namespace Microsoft.AspNetCore.Cryptography.KeyDerivation
{
	public enum KeyDerivationPrf
	{
		HMACSHA1,
		HMACSHA256,
		HMACSHA512
	}
}


// Microsoft.AspNetCore.Cryptography.KeyDerivation\Microsoft.AspNetCore.Cryptography.KeyDerivation.PBKDF2\IPbkdf2Provider.cs
namespace Microsoft.AspNetCore.Cryptography.KeyDerivation.PBKDF2
{
	internal interface IPbkdf2Provider
	{
		byte[] DeriveKey(string password, byte[] salt, KeyDerivationPrf prf, int iterationCount, int numBytesRequested);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\DataProtectionBuilderExtensions.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.AspNetCore.DataProtection
{
	public static class DataProtectionBuilderExtensions
	{
		public static IDataProtectionBuilder AddKeyEscrowSink(this IDataProtectionBuilder builder, IKeyEscrowSink sink)
		{
			throw null;
		}

		public static IDataProtectionBuilder AddKeyEscrowSink(this IDataProtectionBuilder builder, Func<IServiceProvider, IKeyEscrowSink> factory)
		{
			throw null;
		}

		public static IDataProtectionBuilder AddKeyEscrowSink<TImplementation>(this IDataProtectionBuilder builder) where TImplementation : class, IKeyEscrowSink
		{
			throw null;
		}

		public static IDataProtectionBuilder AddKeyManagementOptions(this IDataProtectionBuilder builder, Action<KeyManagementOptions> setupAction)
		{
			throw null;
		}

		public static IDataProtectionBuilder DisableAutomaticKeyGeneration(this IDataProtectionBuilder builder)
		{
			throw null;
		}

		public static IDataProtectionBuilder PersistKeysToFileSystem(this IDataProtectionBuilder builder, DirectoryInfo directory)
		{
			throw null;
		}

		public static IDataProtectionBuilder PersistKeysToRegistry(this IDataProtectionBuilder builder, RegistryKey registryKey)
		{
			throw null;
		}

		public static IDataProtectionBuilder ProtectKeysWithCertificate(this IDataProtectionBuilder builder, X509Certificate2 certificate)
		{
			throw null;
		}

		public static IDataProtectionBuilder ProtectKeysWithCertificate(this IDataProtectionBuilder builder, string thumbprint)
		{
			throw null;
		}

		public static IDataProtectionBuilder ProtectKeysWithDpapi(this IDataProtectionBuilder builder)
		{
			throw null;
		}

		public static IDataProtectionBuilder ProtectKeysWithDpapi(this IDataProtectionBuilder builder, bool protectToLocalMachine)
		{
			throw null;
		}

		public static IDataProtectionBuilder ProtectKeysWithDpapiNG(this IDataProtectionBuilder builder)
		{
			throw null;
		}

		public static IDataProtectionBuilder ProtectKeysWithDpapiNG(this IDataProtectionBuilder builder, string protectionDescriptorRule, DpapiNGProtectionDescriptorFlags flags)
		{
			throw null;
		}

		public static IDataProtectionBuilder SetApplicationName(this IDataProtectionBuilder builder, string applicationName)
		{
			throw null;
		}

		public static IDataProtectionBuilder SetDefaultKeyLifetime(this IDataProtectionBuilder builder, TimeSpan lifetime)
		{
			throw null;
		}

		public static IDataProtectionBuilder UnprotectKeysWithAnyCertificate(this IDataProtectionBuilder builder, params X509Certificate2[] certificates)
		{
			throw null;
		}

		public static IDataProtectionBuilder UseCryptographicAlgorithms(this IDataProtectionBuilder builder, AuthenticatedEncryptorConfiguration configuration)
		{
			throw null;
		}

		[EditorBrowsable(EditorBrowsableState.Advanced)]
		public static IDataProtectionBuilder UseCustomCryptographicAlgorithms(this IDataProtectionBuilder builder, CngCbcAuthenticatedEncryptorConfiguration configuration)
		{
			throw null;
		}

		[EditorBrowsable(EditorBrowsableState.Advanced)]
		public static IDataProtectionBuilder UseCustomCryptographicAlgorithms(this IDataProtectionBuilder builder, CngGcmAuthenticatedEncryptorConfiguration configuration)
		{
			throw null;
		}

		[EditorBrowsable(EditorBrowsableState.Advanced)]
		public static IDataProtectionBuilder UseCustomCryptographicAlgorithms(this IDataProtectionBuilder builder, ManagedAuthenticatedEncryptorConfiguration configuration)
		{
			throw null;
		}

		public static IDataProtectionBuilder UseEphemeralDataProtectionProvider(this IDataProtectionBuilder builder)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\DataProtectionOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection
{
	public class DataProtectionOptions
	{
		public string ApplicationDiscriminator
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\DataProtectionUtilityExtensions.cs
using System;
using System.ComponentModel;

namespace Microsoft.AspNetCore.DataProtection
{
	public static class DataProtectionUtilityExtensions
	{
		[EditorBrowsable(EditorBrowsableState.Never)]
		public static string GetApplicationUniqueIdentifier(this IServiceProvider services)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\EphemeralDataProtectionProvider.cs
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection
{
	public sealed class EphemeralDataProtectionProvider : IDataProtectionProvider
	{
		public EphemeralDataProtectionProvider()
		{
		}

		public EphemeralDataProtectionProvider(ILoggerFactory loggerFactory)
		{
		}

		public IDataProtector CreateProtector(string purpose)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\IDataProtectionBuilder.cs
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.DataProtection
{
	public interface IDataProtectionBuilder
	{
		IServiceCollection Services
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\IPersistedDataProtector.cs
namespace Microsoft.AspNetCore.DataProtection
{
	public interface IPersistedDataProtector : IDataProtectionProvider, IDataProtector
	{
		byte[] DangerousUnprotect(byte[] protectedData, bool ignoreRevocationErrors, out bool requiresMigration, out bool wasRevoked);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\IRegistryPolicyResolver.cs
namespace Microsoft.AspNetCore.DataProtection
{
	internal interface IRegistryPolicyResolver
	{
		RegistryPolicy ResolvePolicy();
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\ISecret.cs
using System;

namespace Microsoft.AspNetCore.DataProtection
{
	public interface ISecret : IDisposable
	{
		int Length
		{
			get;
		}

		void WriteSecretIntoBuffer(ArraySegment<byte> buffer);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection\Secret.cs
using System;

namespace Microsoft.AspNetCore.DataProtection
{
	public sealed class Secret : ISecret, IDisposable
	{
		public int Length
		{
			get
			{
				throw null;
			}
		}

		public Secret(ISecret secret)
		{
		}

		public Secret(ArraySegment<byte> value)
		{
		}

		public unsafe Secret(byte* secret, int secretLength)
		{
		}

		public Secret(byte[] value)
		{
		}

		public void Dispose()
		{
		}

		public static Secret Random(int numBytes)
		{
			throw null;
		}

		public void WriteSecretIntoBuffer(ArraySegment<byte> buffer)
		{
		}

		public unsafe void WriteSecretIntoBuffer(byte* buffer, int bufferLength)
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\AuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class AuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		public AuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\CngCbcAuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class CngCbcAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		public CngCbcAuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\CngGcmAuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class CngGcmAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		public CngGcmAuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\EncryptionAlgorithm.cs
namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public enum EncryptionAlgorithm
	{
		AES_128_CBC,
		AES_192_CBC,
		AES_256_CBC,
		AES_128_GCM,
		AES_192_GCM,
		AES_256_GCM
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\IAuthenticatedEncryptor.cs
using System;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public interface IAuthenticatedEncryptor
	{
		byte[] Decrypt(ArraySegment<byte> ciphertext, ArraySegment<byte> additionalAuthenticatedData);

		byte[] Encrypt(ArraySegment<byte> plaintext, ArraySegment<byte> additionalAuthenticatedData);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\IAuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public interface IAuthenticatedEncryptorFactory
	{
		IAuthenticatedEncryptor CreateEncryptorInstance(IKey key);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\IOptimizedAuthenticatedEncryptor.cs
using System;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	internal interface IOptimizedAuthenticatedEncryptor : IAuthenticatedEncryptor
	{
		byte[] Encrypt(ArraySegment<byte> plaintext, ArraySegment<byte> additionalAuthenticatedData, uint preBufferSize, uint postBufferSize);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\ManagedAuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class ManagedAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		public ManagedAuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\ValidationAlgorithm.cs
namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public enum ValidationAlgorithm
	{
		HMACSHA256,
		HMACSHA512
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\AlgorithmConfiguration.cs
namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public abstract class AlgorithmConfiguration
	{
		public abstract IAuthenticatedEncryptorDescriptor CreateNewDescriptor();
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\AuthenticatedEncryptorConfiguration.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class AuthenticatedEncryptorConfiguration : AlgorithmConfiguration
	{
		public EncryptionAlgorithm EncryptionAlgorithm
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ValidationAlgorithm ValidationAlgorithm
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\AuthenticatedEncryptorDescriptor.cs
namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class AuthenticatedEncryptorDescriptor : IAuthenticatedEncryptorDescriptor
	{
		public AuthenticatedEncryptorDescriptor(AuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
		}

		public XmlSerializedDescriptorInfo ExportToXml()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\AuthenticatedEncryptorDescriptorDeserializer.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class AuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
	{
		public IAuthenticatedEncryptorDescriptor ImportFromXml(XElement element)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngCbcAuthenticatedEncryptorConfiguration.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngCbcAuthenticatedEncryptorConfiguration : AlgorithmConfiguration
	{
		public string EncryptionAlgorithm
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int EncryptionAlgorithmKeySize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string EncryptionAlgorithmProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string HashAlgorithm
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string HashAlgorithmProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngCbcAuthenticatedEncryptorDescriptor.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngCbcAuthenticatedEncryptorDescriptor : IAuthenticatedEncryptorDescriptor
	{
		internal CngCbcAuthenticatedEncryptorConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal ISecret MasterKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CngCbcAuthenticatedEncryptorDescriptor(CngCbcAuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
		}

		public XmlSerializedDescriptorInfo ExportToXml()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngCbcAuthenticatedEncryptorDescriptorDeserializer.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngCbcAuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
	{
		public IAuthenticatedEncryptorDescriptor ImportFromXml(XElement element)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngGcmAuthenticatedEncryptorConfiguration.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngGcmAuthenticatedEncryptorConfiguration : AlgorithmConfiguration
	{
		public string EncryptionAlgorithm
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int EncryptionAlgorithmKeySize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string EncryptionAlgorithmProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngGcmAuthenticatedEncryptorDescriptor.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngGcmAuthenticatedEncryptorDescriptor : IAuthenticatedEncryptorDescriptor
	{
		internal CngGcmAuthenticatedEncryptorConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal ISecret MasterKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CngGcmAuthenticatedEncryptorDescriptor(CngGcmAuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
		}

		public XmlSerializedDescriptorInfo ExportToXml()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngGcmAuthenticatedEncryptorDescriptorDeserializer.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngGcmAuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
	{
		public IAuthenticatedEncryptorDescriptor ImportFromXml(XElement element)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\IAuthenticatedEncryptorDescriptor.cs
namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public interface IAuthenticatedEncryptorDescriptor
	{
		XmlSerializedDescriptorInfo ExportToXml();
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\IAuthenticatedEncryptorDescriptorDeserializer.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public interface IAuthenticatedEncryptorDescriptorDeserializer
	{
		IAuthenticatedEncryptorDescriptor ImportFromXml(XElement element);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\ManagedAuthenticatedEncryptorConfiguration.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class ManagedAuthenticatedEncryptorConfiguration : AlgorithmConfiguration
	{
		public int EncryptionAlgorithmKeySize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Type EncryptionAlgorithmType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Type ValidationAlgorithmType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\ManagedAuthenticatedEncryptorDescriptor.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class ManagedAuthenticatedEncryptorDescriptor : IAuthenticatedEncryptorDescriptor
	{
		internal ManagedAuthenticatedEncryptorConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal ISecret MasterKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ManagedAuthenticatedEncryptorDescriptor(ManagedAuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
		}

		public XmlSerializedDescriptorInfo ExportToXml()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\ManagedAuthenticatedEncryptorDescriptorDeserializer.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class ManagedAuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
	{
		public IAuthenticatedEncryptorDescriptor ImportFromXml(XElement element)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\XmlExtensions.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public static class XmlExtensions
	{
		public static void MarkAsRequiresEncryption(this XElement element)
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\XmlSerializedDescriptorInfo.cs
using System;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class XmlSerializedDescriptorInfo
	{
		public Type DeserializerType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public XElement SerializedDescriptorElement
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public XmlSerializedDescriptorInfo(XElement serializedDescriptorElement, Type deserializerType)
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Cng\IBCryptGenRandom.cs
namespace Microsoft.AspNetCore.DataProtection.Cng
{
	internal interface IBCryptGenRandom
	{
		unsafe void GenRandom(byte* pbBuffer, uint cbBuffer);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Cng.Internal\CngAuthenticatedEncryptorBase.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using System;

namespace Microsoft.AspNetCore.DataProtection.Cng.Internal
{
	internal abstract class CngAuthenticatedEncryptorBase : IAuthenticatedEncryptor, IOptimizedAuthenticatedEncryptor, IDisposable
	{
		public byte[] Decrypt(ArraySegment<byte> ciphertext, ArraySegment<byte> additionalAuthenticatedData)
		{
			throw null;
		}

		protected unsafe abstract byte[] DecryptImpl(byte* pbCiphertext, uint cbCiphertext, byte* pbAdditionalAuthenticatedData, uint cbAdditionalAuthenticatedData);

		public abstract void Dispose();

		public byte[] Encrypt(ArraySegment<byte> plaintext, ArraySegment<byte> additionalAuthenticatedData)
		{
			throw null;
		}

		public byte[] Encrypt(ArraySegment<byte> plaintext, ArraySegment<byte> additionalAuthenticatedData, uint preBufferSize, uint postBufferSize)
		{
			throw null;
		}

		protected unsafe abstract byte[] EncryptImpl(byte* pbPlaintext, uint cbPlaintext, byte* pbAdditionalAuthenticatedData, uint cbAdditionalAuthenticatedData, uint cbPreBuffer, uint cbPostBuffer);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Internal\IActivator.cs
using System;

namespace Microsoft.AspNetCore.DataProtection.Internal
{
	public interface IActivator
	{
		object CreateInstance(Type expectedBaseType, string implementationTypeName);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement\IKey.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using System;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement
{
	public interface IKey
	{
		DateTimeOffset ActivationDate
		{
			get;
		}

		DateTimeOffset CreationDate
		{
			get;
		}

		IAuthenticatedEncryptorDescriptor Descriptor
		{
			get;
		}

		DateTimeOffset ExpirationDate
		{
			get;
		}

		bool IsRevoked
		{
			get;
		}

		Guid KeyId
		{
			get;
		}

		IAuthenticatedEncryptor CreateEncryptor();
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement\IKeyEscrowSink.cs
using System;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement
{
	public interface IKeyEscrowSink
	{
		void Store(Guid keyId, XElement element);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement\IKeyManager.cs
using System;
using System.Collections.Generic;
using System.Threading;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement
{
	public interface IKeyManager
	{
		IKey CreateNewKey(DateTimeOffset activationDate, DateTimeOffset expirationDate);

		IReadOnlyCollection<IKey> GetAllKeys();

		CancellationToken GetCacheExpirationToken();

		void RevokeAllKeys(DateTimeOffset revocationDate, string reason = null);

		void RevokeKey(Guid keyId, string reason = null);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement\KeyBase.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement
{
	internal abstract class KeyBase : IKey
	{
		public DateTimeOffset ActivationDate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DateTimeOffset CreationDate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IAuthenticatedEncryptorDescriptor Descriptor
		{
			get
			{
				throw null;
			}
		}

		public DateTimeOffset ExpirationDate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsRevoked
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Guid KeyId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public KeyBase(Guid keyId, DateTimeOffset creationDate, DateTimeOffset activationDate, DateTimeOffset expirationDate, Lazy<IAuthenticatedEncryptorDescriptor> lazyDescriptor, IEnumerable<IAuthenticatedEncryptorFactory> encryptorFactories)
		{
		}

		public IAuthenticatedEncryptor CreateEncryptor()
		{
			throw null;
		}

		internal void SetRevoked()
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement\KeyManagementOptions.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement
{
	public class KeyManagementOptions
	{
		public AlgorithmConfiguration AuthenticatedEncryptorConfiguration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<IAuthenticatedEncryptorFactory> AuthenticatedEncryptorFactories
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool AutoGenerateKeys
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<IKeyEscrowSink> KeyEscrowSinks
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TimeSpan NewKeyLifetime
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IXmlEncryptor XmlEncryptor
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IXmlRepository XmlRepository
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement\XmlKeyManager.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.AspNetCore.DataProtection.KeyManagement.Internal;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement
{
	public sealed class XmlKeyManager : IKeyManager, IInternalXmlKeyManager
	{
		internal static readonly XName ActivationDateElementName;

		internal static readonly XName CreationDateElementName;

		internal static readonly XName DescriptorElementName;

		internal static readonly XName DeserializerTypeAttributeName;

		internal static readonly XName ExpirationDateElementName;

		internal static readonly XName IdAttributeName;

		internal static readonly XName KeyElementName;

		internal static readonly XName ReasonElementName;

		internal static readonly XName RevocationDateElementName;

		internal static readonly XName RevocationElementName;

		internal static readonly XName VersionAttributeName;

		internal IXmlEncryptor KeyEncryptor
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal IXmlRepository KeyRepository
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public XmlKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator)
		{
		}

		public XmlKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator, ILoggerFactory loggerFactory)
		{
		}

		public IKey CreateNewKey(DateTimeOffset activationDate, DateTimeOffset expirationDate)
		{
			throw null;
		}

		public IReadOnlyCollection<IKey> GetAllKeys()
		{
			throw null;
		}

		public CancellationToken GetCacheExpirationToken()
		{
			throw null;
		}

		IKey IInternalXmlKeyManager.CreateNewKey(Guid keyId, DateTimeOffset creationDate, DateTimeOffset activationDate, DateTimeOffset expirationDate)
		{
			throw null;
		}

		IAuthenticatedEncryptorDescriptor IInternalXmlKeyManager.DeserializeDescriptorFromKeyElement(XElement keyElement)
		{
			throw null;
		}

		void IInternalXmlKeyManager.RevokeSingleKey(Guid keyId, DateTimeOffset revocationDate, string reason)
		{
		}

		public void RevokeAllKeys(DateTimeOffset revocationDate, string reason = null)
		{
		}

		public void RevokeKey(Guid keyId, string reason = null)
		{
		}

		internal XmlKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator, ILoggerFactory loggerFactory, IInternalXmlKeyManager internalXmlKeyManager)
		{
		}

		internal XmlKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator, ILoggerFactory loggerFactory, IDefaultKeyStorageDirectories keyStorageDirectories)
		{
		}

		internal KeyValuePair<IXmlRepository, IXmlEncryptor> GetFallbackKeyRepositoryEncryptorPair()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement.Internal\CacheableKeyRing.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
	public sealed class CacheableKeyRing
	{
		internal DateTime ExpirationTimeUtc
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal IKeyRing KeyRing
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal CacheableKeyRing()
		{
		}

		internal CacheableKeyRing(CancellationToken expirationToken, DateTimeOffset expirationTime, IKey defaultKey, IEnumerable<IKey> allKeys)
		{
		}

		internal CacheableKeyRing(CancellationToken expirationToken, DateTimeOffset expirationTime, IKeyRing keyRing)
		{
		}

		internal static bool IsValid(CacheableKeyRing keyRing, DateTime utcNow)
		{
			throw null;
		}

		internal CacheableKeyRing WithTemporaryExtendedLifetime(DateTimeOffset now)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement.Internal\DefaultKeyResolution.cs
namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
	public struct DefaultKeyResolution
	{
		public IKey DefaultKey;

		public IKey FallbackKey;

		public bool ShouldGenerateNewKey;
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement.Internal\ICacheableKeyRingProvider.cs
using System;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
	public interface ICacheableKeyRingProvider
	{
		CacheableKeyRing GetCacheableKeyRing(DateTimeOffset now);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement.Internal\IDefaultKeyResolver.cs
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
	public interface IDefaultKeyResolver
	{
		DefaultKeyResolution ResolveDefaultKeyPolicy(DateTimeOffset now, IEnumerable<IKey> allKeys);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement.Internal\IInternalXmlKeyManager.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using System;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
	public interface IInternalXmlKeyManager
	{
		IKey CreateNewKey(Guid keyId, DateTimeOffset creationDate, DateTimeOffset activationDate, DateTimeOffset expirationDate);

		IAuthenticatedEncryptorDescriptor DeserializeDescriptorFromKeyElement(XElement keyElement);

		void RevokeSingleKey(Guid keyId, DateTimeOffset revocationDate, string reason);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement.Internal\IKeyRing.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using System;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
	public interface IKeyRing
	{
		IAuthenticatedEncryptor DefaultAuthenticatedEncryptor
		{
			get;
		}

		Guid DefaultKeyId
		{
			get;
		}

		IAuthenticatedEncryptor GetAuthenticatedEncryptorByKeyId(Guid keyId, out bool isRevoked);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.KeyManagement.Internal\IKeyRingProvider.cs
namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
	public interface IKeyRingProvider
	{
		IKeyRing GetCurrentKeyRing();
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Managed\IManagedGenRandom.cs
namespace Microsoft.AspNetCore.DataProtection.Managed
{
	internal interface IManagedGenRandom
	{
		byte[] GenRandom(int numBytes);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Repositories\FileSystemXmlRepository.cs
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.Repositories
{
	public class FileSystemXmlRepository : IXmlRepository
	{
		public static DirectoryInfo DefaultKeyStorageDirectory
		{
			get
			{
				throw null;
			}
		}

		public DirectoryInfo Directory
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FileSystemXmlRepository(DirectoryInfo directory, ILoggerFactory loggerFactory)
		{
		}

		public virtual IReadOnlyCollection<XElement> GetAllElements()
		{
			throw null;
		}

		public virtual void StoreElement(XElement element, string friendlyName)
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Repositories\IDefaultKeyStorageDirectories.cs
using System.IO;

namespace Microsoft.AspNetCore.DataProtection.Repositories
{
	internal interface IDefaultKeyStorageDirectories
	{
		DirectoryInfo GetKeyStorageDirectory();

		DirectoryInfo GetKeyStorageDirectoryForAzureWebSites();
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Repositories\IXmlRepository.cs
using System.Collections.Generic;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.Repositories
{
	public interface IXmlRepository
	{
		IReadOnlyCollection<XElement> GetAllElements();

		void StoreElement(XElement element, string friendlyName);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.Repositories\RegistryXmlRepository.cs
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.Repositories
{
	public class RegistryXmlRepository : IXmlRepository
	{
		public static RegistryKey DefaultRegistryKey
		{
			get
			{
				throw null;
			}
		}

		public RegistryKey RegistryKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RegistryXmlRepository(RegistryKey registryKey, ILoggerFactory loggerFactory)
		{
		}

		public virtual IReadOnlyCollection<XElement> GetAllElements()
		{
			throw null;
		}

		public virtual void StoreElement(XElement element, string friendlyName)
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.SP800_108\ISP800_108_CTR_HMACSHA512Provider.cs
using System;

namespace Microsoft.AspNetCore.DataProtection.SP800_108
{
	internal interface ISP800_108_CTR_HMACSHA512Provider : IDisposable
	{
		unsafe void DeriveKey(byte* pbLabel, uint cbLabel, byte* pbContext, uint cbContext, byte* pbDerivedKey, uint cbDerivedKey);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\CertificateResolver.cs
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public class CertificateResolver : ICertificateResolver
	{
		public virtual X509Certificate2 ResolveCertificate(string thumbprint)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\CertificateXmlEncryptor.cs
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class CertificateXmlEncryptor : IXmlEncryptor, IInternalCertificateXmlEncryptor
	{
		public CertificateXmlEncryptor(X509Certificate2 certificate, ILoggerFactory loggerFactory)
		{
		}

		public CertificateXmlEncryptor(string thumbprint, ICertificateResolver certificateResolver, ILoggerFactory loggerFactory)
		{
		}

		public EncryptedXmlInfo Encrypt(XElement plaintextElement)
		{
			throw null;
		}

		EncryptedData IInternalCertificateXmlEncryptor.PerformEncryption(EncryptedXml encryptedXml, XmlElement elementToEncrypt)
		{
			throw null;
		}

		internal CertificateXmlEncryptor(ILoggerFactory loggerFactory, IInternalCertificateXmlEncryptor encryptor)
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\DpapiNGProtectionDescriptorFlags.cs
using System;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	[Flags]
	public enum DpapiNGProtectionDescriptorFlags
	{
		None = 0x0,
		NamedDescriptor = 0x1,
		MachineKey = 0x20
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\DpapiNGXmlDecryptor.cs
using System;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class DpapiNGXmlDecryptor : IXmlDecryptor
	{
		public DpapiNGXmlDecryptor()
		{
		}

		public DpapiNGXmlDecryptor(IServiceProvider services)
		{
		}

		public XElement Decrypt(XElement encryptedElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\DpapiNGXmlEncryptor.cs
using Microsoft.Extensions.Logging;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class DpapiNGXmlEncryptor : IXmlEncryptor
	{
		public DpapiNGXmlEncryptor(string protectionDescriptorRule, DpapiNGProtectionDescriptorFlags flags, ILoggerFactory loggerFactory)
		{
		}

		public EncryptedXmlInfo Encrypt(XElement plaintextElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\DpapiXmlDecryptor.cs
using System;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class DpapiXmlDecryptor : IXmlDecryptor
	{
		public DpapiXmlDecryptor()
		{
		}

		public DpapiXmlDecryptor(IServiceProvider services)
		{
		}

		public XElement Decrypt(XElement encryptedElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\DpapiXmlEncryptor.cs
using Microsoft.Extensions.Logging;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class DpapiXmlEncryptor : IXmlEncryptor
	{
		public DpapiXmlEncryptor(bool protectToLocalMachine, ILoggerFactory loggerFactory)
		{
		}

		public EncryptedXmlInfo Encrypt(XElement plaintextElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\EncryptedXmlDecryptor.cs
using System;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class EncryptedXmlDecryptor : IXmlDecryptor
	{
		public EncryptedXmlDecryptor()
		{
		}

		public EncryptedXmlDecryptor(IServiceProvider services)
		{
		}

		public XElement Decrypt(XElement encryptedElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\EncryptedXmlInfo.cs
using System;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class EncryptedXmlInfo
	{
		public Type DecryptorType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public XElement EncryptedElement
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public EncryptedXmlInfo(XElement encryptedElement, Type decryptorType)
		{
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\ICertificateResolver.cs
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public interface ICertificateResolver
	{
		X509Certificate2 ResolveCertificate(string thumbprint);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\IInternalCertificateXmlEncryptor.cs
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	internal interface IInternalCertificateXmlEncryptor
	{
		EncryptedData PerformEncryption(EncryptedXml encryptedXml, XmlElement elementToEncrypt);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\IInternalEncryptedXmlDecryptor.cs
using System.Security.Cryptography.Xml;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	internal interface IInternalEncryptedXmlDecryptor
	{
		void PerformPreDecryptionSetup(EncryptedXml encryptedXml);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\IXmlDecryptor.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public interface IXmlDecryptor
	{
		XElement Decrypt(XElement encryptedElement);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\IXmlEncryptor.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public interface IXmlEncryptor
	{
		EncryptedXmlInfo Encrypt(XElement plaintextElement);
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\NullXmlDecryptor.cs
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class NullXmlDecryptor : IXmlDecryptor
	{
		public XElement Decrypt(XElement encryptedElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\NullXmlEncryptor.cs
using System;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class NullXmlEncryptor : IXmlEncryptor
	{
		public NullXmlEncryptor()
		{
		}

		public NullXmlEncryptor(IServiceProvider services)
		{
		}

		public EncryptedXmlInfo Encrypt(XElement plaintextElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.Extensions.DependencyInjection\DataProtectionServiceCollectionExtensions.cs
using Microsoft.AspNetCore.DataProtection;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class DataProtectionServiceCollectionExtensions
	{
		public static IDataProtectionBuilder AddDataProtection(this IServiceCollection services)
		{
			throw null;
		}

		public static IDataProtectionBuilder AddDataProtection(this IServiceCollection services, Action<DataProtectionOptions> setupAction)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection.Abstractions\Microsoft.AspNetCore.DataProtection\DataProtectionCommonExtensions.cs
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.DataProtection
{
	public static class DataProtectionCommonExtensions
	{
		public static IDataProtector CreateProtector(this IDataProtectionProvider provider, IEnumerable<string> purposes)
		{
			throw null;
		}

		public static IDataProtector CreateProtector(this IDataProtectionProvider provider, string purpose, params string[] subPurposes)
		{
			throw null;
		}

		public static IDataProtectionProvider GetDataProtectionProvider(this IServiceProvider services)
		{
			throw null;
		}

		public static IDataProtector GetDataProtector(this IServiceProvider services, IEnumerable<string> purposes)
		{
			throw null;
		}

		public static IDataProtector GetDataProtector(this IServiceProvider services, string purpose, params string[] subPurposes)
		{
			throw null;
		}

		public static string Protect(this IDataProtector protector, string plaintext)
		{
			throw null;
		}

		public static string Unprotect(this IDataProtector protector, string protectedData)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection.Abstractions\Microsoft.AspNetCore.DataProtection\IDataProtectionProvider.cs
namespace Microsoft.AspNetCore.DataProtection
{
	public interface IDataProtectionProvider
	{
		IDataProtector CreateProtector(string purpose);
	}
}


// Microsoft.AspNetCore.DataProtection.Abstractions\Microsoft.AspNetCore.DataProtection\IDataProtector.cs
namespace Microsoft.AspNetCore.DataProtection
{
	public interface IDataProtector : IDataProtectionProvider
	{
		byte[] Protect(byte[] plaintext);

		byte[] Unprotect(byte[] protectedData);
	}
}


// Microsoft.AspNetCore.DataProtection.Abstractions\Microsoft.AspNetCore.DataProtection.Infrastructure\IApplicationDiscriminator.cs
using System.ComponentModel;

namespace Microsoft.AspNetCore.DataProtection.Infrastructure
{
	[EditorBrowsable(EditorBrowsableState.Never)]
	public interface IApplicationDiscriminator
	{
		string Discriminator
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.DataProtection.Extensions\Microsoft.AspNetCore.DataProtection\DataProtectionAdvancedExtensions.cs
using System;

namespace Microsoft.AspNetCore.DataProtection
{
	public static class DataProtectionAdvancedExtensions
	{
		public static byte[] Protect(this ITimeLimitedDataProtector protector, byte[] plaintext, TimeSpan lifetime)
		{
			throw null;
		}

		public static string Protect(this ITimeLimitedDataProtector protector, string plaintext, DateTimeOffset expiration)
		{
			throw null;
		}

		public static string Protect(this ITimeLimitedDataProtector protector, string plaintext, TimeSpan lifetime)
		{
			throw null;
		}

		public static ITimeLimitedDataProtector ToTimeLimitedDataProtector(this IDataProtector protector)
		{
			throw null;
		}

		public static string Unprotect(this ITimeLimitedDataProtector protector, string protectedData, out DateTimeOffset expiration)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection.Extensions\Microsoft.AspNetCore.DataProtection\DataProtectionProvider.cs
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.AspNetCore.DataProtection
{
	public static class DataProtectionProvider
	{
		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory, Action<IDataProtectionBuilder> setupAction)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory, Action<IDataProtectionBuilder> setupAction, X509Certificate2 certificate)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory, X509Certificate2 certificate)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(string applicationName)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(string applicationName, X509Certificate2 certificate)
		{
			throw null;
		}

		internal static IDataProtectionProvider CreateProvider(DirectoryInfo keyDirectory, Action<IDataProtectionBuilder> setupAction, X509Certificate2 certificate)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection.Extensions\Microsoft.AspNetCore.DataProtection\ITimeLimitedDataProtector.cs
using System;

namespace Microsoft.AspNetCore.DataProtection
{
	public interface ITimeLimitedDataProtector : IDataProtectionProvider, IDataProtector
	{
		new ITimeLimitedDataProtector CreateProtector(string purpose);

		byte[] Protect(byte[] plaintext, DateTimeOffset expiration);

		byte[] Unprotect(byte[] protectedData, out DateTimeOffset expiration);
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\DeveloperExceptionPageExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class DeveloperExceptionPageExtensions
	{
		public static IApplicationBuilder UseDeveloperExceptionPage(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseDeveloperExceptionPage(this IApplicationBuilder app, DeveloperExceptionPageOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\DeveloperExceptionPageOptions.cs
using Microsoft.Extensions.FileProviders;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class DeveloperExceptionPageOptions
	{
		public IFileProvider FileProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int SourceCodeLineCount
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public DeveloperExceptionPageOptions()
		{
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\ExceptionHandlerExtensions.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class ExceptionHandlerExtensions
	{
		public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app, ExceptionHandlerOptions options)
		{
			throw null;
		}

		public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app, Action<IApplicationBuilder> configure)
		{
			throw null;
		}

		public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app, string errorHandlingPath)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\ExceptionHandlerOptions.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class ExceptionHandlerOptions
	{
		public RequestDelegate ExceptionHandler
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public PathString ExceptionHandlingPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\StatusCodePagesExtensions.cs
using Microsoft.AspNetCore.Diagnostics;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder
{
	public static class StatusCodePagesExtensions
	{
		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app, StatusCodePagesOptions options)
		{
			throw null;
		}

		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app, Action<IApplicationBuilder> configuration)
		{
			throw null;
		}

		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app, Func<StatusCodeContext, Task> handler)
		{
			throw null;
		}

		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app, string contentType, string bodyFormat)
		{
			throw null;
		}

		public static IApplicationBuilder UseStatusCodePagesWithRedirects(this IApplicationBuilder app, string locationFormat)
		{
			throw null;
		}

		public static IApplicationBuilder UseStatusCodePagesWithReExecute(this IApplicationBuilder app, string pathFormat, string queryFormat = null)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\StatusCodePagesOptions.cs
using Microsoft.AspNetCore.Diagnostics;
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder
{
	public class StatusCodePagesOptions
	{
		public Func<StatusCodeContext, Task> HandleAsync
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\WelcomePageExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Builder
{
	public static class WelcomePageExtensions
	{
		public static IApplicationBuilder UseWelcomePage(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseWelcomePage(this IApplicationBuilder app, WelcomePageOptions options)
		{
			throw null;
		}

		public static IApplicationBuilder UseWelcomePage(this IApplicationBuilder app, PathString path)
		{
			throw null;
		}

		public static IApplicationBuilder UseWelcomePage(this IApplicationBuilder app, string path)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\WelcomePageOptions.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class WelcomePageOptions
	{
		public PathString Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\DeveloperExceptionPageMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class DeveloperExceptionPageMiddleware
	{
		public DeveloperExceptionPageMiddleware(RequestDelegate next, IOptions<DeveloperExceptionPageOptions> options, ILoggerFactory loggerFactory, IWebHostEnvironment hostingEnvironment, DiagnosticSource diagnosticSource, IEnumerable<IDeveloperPageExceptionFilter> filters)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\ExceptionHandlerFeature.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class ExceptionHandlerFeature : IExceptionHandlerFeature, IExceptionHandlerPathFeature
	{
		public Exception Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\ExceptionHandlerMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class ExceptionHandlerMiddleware
	{
		public ExceptionHandlerMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IOptions<ExceptionHandlerOptions> options, DiagnosticListener diagnosticListener)
		{
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\StatusCodeContext.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class StatusCodeContext
	{
		public HttpContext HttpContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RequestDelegate Next
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public StatusCodePagesOptions Options
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public StatusCodeContext(HttpContext context, StatusCodePagesOptions options, RequestDelegate next)
		{
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\StatusCodePagesFeature.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class StatusCodePagesFeature : IStatusCodePagesFeature
	{
		public bool Enabled
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\StatusCodePagesMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class StatusCodePagesMiddleware
	{
		public StatusCodePagesMiddleware(RequestDelegate next, IOptions<StatusCodePagesOptions> options)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\StatusCodeReExecuteFeature.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class StatusCodeReExecuteFeature : IStatusCodeReExecuteFeature
	{
		public string OriginalPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string OriginalPathBase
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string OriginalQueryString
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\WelcomePageMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class WelcomePageMiddleware
	{
		public WelcomePageMiddleware(RequestDelegate next, IOptions<WelcomePageOptions> options)
		{
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\CompilationFailure.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class CompilationFailure
	{
		public string CompiledContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string FailureSummary
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IEnumerable<DiagnosticMessage> Messages
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string SourceFileContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string SourceFilePath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CompilationFailure(string sourceFilePath, string sourceFileContent, string compiledContent, IEnumerable<DiagnosticMessage> messages)
		{
		}

		public CompilationFailure(string sourceFilePath, string sourceFileContent, string compiledContent, IEnumerable<DiagnosticMessage> messages, string failureSummary)
		{
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\DiagnosticMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class DiagnosticMessage
	{
		public int EndColumn
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int EndLine
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string FormattedMessage
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Message
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string SourceFilePath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int StartColumn
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int StartLine
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DiagnosticMessage(string message, string formattedMessage, string filePath, int startLine, int startColumn, int endLine, int endColumn)
		{
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\ErrorContext.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class ErrorContext
	{
		public Exception Exception
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HttpContext HttpContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ErrorContext(HttpContext httpContext, Exception exception)
		{
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\ICompilationException.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Diagnostics
{
	public interface ICompilationException
	{
		IEnumerable<CompilationFailure> CompilationFailures
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\IDeveloperPageExceptionFilter.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics
{
	public interface IDeveloperPageExceptionFilter
	{
		Task HandleExceptionAsync(ErrorContext errorContext, Func<ErrorContext, Task> next);
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\IExceptionHandlerFeature.cs
using System;

namespace Microsoft.AspNetCore.Diagnostics
{
	public interface IExceptionHandlerFeature
	{
		Exception Error
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\IExceptionHandlerPathFeature.cs
namespace Microsoft.AspNetCore.Diagnostics
{
	public interface IExceptionHandlerPathFeature : IExceptionHandlerFeature
	{
		string Path
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\IStatusCodePagesFeature.cs
namespace Microsoft.AspNetCore.Diagnostics
{
	public interface IStatusCodePagesFeature
	{
		bool Enabled
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\IStatusCodeReExecuteFeature.cs
namespace Microsoft.AspNetCore.Diagnostics
{
	public interface IStatusCodeReExecuteFeature
	{
		string OriginalPath
		{
			get;
			set;
		}

		string OriginalPathBase
		{
			get;
			set;
		}

		string OriginalQueryString
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.HealthChecks\Microsoft.AspNetCore.Builder\HealthCheckApplicationBuilderExtensions.cs
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Builder
{
	public static class HealthCheckApplicationBuilderExtensions
	{
		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path)
		{
			throw null;
		}

		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path, HealthCheckOptions options)
		{
			throw null;
		}

		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path, int port)
		{
			throw null;
		}

		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path, int port, HealthCheckOptions options)
		{
			throw null;
		}

		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path, string port)
		{
			throw null;
		}

		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path, string port, HealthCheckOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.HealthChecks\Microsoft.AspNetCore.Builder\HealthCheckEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder
{
	public static class HealthCheckEndpointRouteBuilderExtensions
	{
		public static IEndpointConventionBuilder MapHealthChecks(this IEndpointRouteBuilder endpoints, string pattern)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapHealthChecks(this IEndpointRouteBuilder endpoints, string pattern, HealthCheckOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.HealthChecks\Microsoft.AspNetCore.Diagnostics.HealthChecks\HealthCheckMiddleware.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics.HealthChecks
{
	public class HealthCheckMiddleware
	{
		public HealthCheckMiddleware(RequestDelegate next, IOptions<HealthCheckOptions> healthCheckOptions, HealthCheckService healthCheckService)
		{
		}

		[DebuggerStepThrough]
		public Task InvokeAsync(HttpContext httpContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.HealthChecks\Microsoft.AspNetCore.Diagnostics.HealthChecks\HealthCheckOptions.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics.HealthChecks
{
	public class HealthCheckOptions
	{
		public bool AllowCachingResponses
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Func<HealthCheckRegistration, bool> Predicate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Func<HttpContext, HealthReport, Task> ResponseWriter
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IDictionary<HealthStatus, int> ResultStatusCodes
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.HostFiltering\Microsoft.AspNetCore.Builder\HostFilteringBuilderExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class HostFilteringBuilderExtensions
	{
		public static IApplicationBuilder UseHostFiltering(this IApplicationBuilder app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HostFiltering\Microsoft.AspNetCore.Builder\HostFilteringServicesExtensions.cs
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class HostFilteringServicesExtensions
	{
		public static IServiceCollection AddHostFiltering(this IServiceCollection services, Action<HostFilteringOptions> configureOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HostFiltering\Microsoft.AspNetCore.HostFiltering\HostFilteringMiddleware.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HostFiltering
{
	public class HostFilteringMiddleware
	{
		public HostFilteringMiddleware(RequestDelegate next, ILogger<HostFilteringMiddleware> logger, IOptionsMonitor<HostFilteringOptions> optionsMonitor)
		{
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HostFiltering\Microsoft.AspNetCore.HostFiltering\HostFilteringOptions.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.HostFiltering
{
	public class HostFilteringOptions
	{
		public IList<string> AllowedHosts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool AllowEmptyHosts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool IncludeFailureMessage
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\DelegateStartup.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public class DelegateStartup : StartupBase<IServiceCollection>
	{
		public DelegateStartup(IServiceProviderFactory<IServiceCollection> factory, Action<IApplicationBuilder> configureApp)
			: base((IServiceProviderFactory<IServiceCollection>)null)
		{
		}

		public override void Configure(IApplicationBuilder app)
		{
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\ISupportsStartup.cs
using Microsoft.AspNetCore.Builder;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	internal interface ISupportsStartup
	{
		IWebHostBuilder Configure(Action<WebHostBuilderContext, IApplicationBuilder> configure);

		IWebHostBuilder UseStartup(Type startupType);
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\ISupportsUseDefaultServiceProvider.cs
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	internal interface ISupportsUseDefaultServiceProvider
	{
		IWebHostBuilder UseDefaultServiceProvider(Action<WebHostBuilderContext, ServiceProviderOptions> configure);
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\StartupBase.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public abstract class StartupBase : IStartup
	{
		public abstract void Configure(IApplicationBuilder app);

		public virtual void ConfigureServices(IServiceCollection services)
		{
		}

		public virtual IServiceProvider CreateServiceProvider(IServiceCollection services)
		{
			throw null;
		}

		IServiceProvider IStartup.ConfigureServices(IServiceCollection services)
		{
			throw null;
		}
	}
	public abstract class StartupBase<TBuilder> : StartupBase
	{
		public StartupBase(IServiceProviderFactory<TBuilder> factory)
		{
		}

		public virtual void ConfigureContainer(TBuilder builder)
		{
		}

		public override IServiceProvider CreateServiceProvider(IServiceCollection services)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\WebHostBuilder.cs
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public class WebHostBuilder : IWebHostBuilder
	{
		public WebHostBuilder()
		{
		}

		public IWebHost Build()
		{
			throw null;
		}

		public IWebHostBuilder ConfigureAppConfiguration(Action<WebHostBuilderContext, IConfigurationBuilder> configureDelegate)
		{
			throw null;
		}

		public IWebHostBuilder ConfigureServices(Action<WebHostBuilderContext, IServiceCollection> configureServices)
		{
			throw null;
		}

		public IWebHostBuilder ConfigureServices(Action<IServiceCollection> configureServices)
		{
			throw null;
		}

		public string GetSetting(string key)
		{
			throw null;
		}

		public IWebHostBuilder UseSetting(string key, string value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\WebHostBuilderExtensions.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public static class WebHostBuilderExtensions
	{
		public static IWebHostBuilder Configure(this IWebHostBuilder hostBuilder, Action<IApplicationBuilder> configureApp)
		{
			throw null;
		}

		public static IWebHostBuilder Configure(this IWebHostBuilder hostBuilder, Action<WebHostBuilderContext, IApplicationBuilder> configureApp)
		{
			throw null;
		}

		public static IWebHostBuilder ConfigureAppConfiguration(this IWebHostBuilder hostBuilder, Action<IConfigurationBuilder> configureDelegate)
		{
			throw null;
		}

		public static IWebHostBuilder ConfigureLogging(this IWebHostBuilder hostBuilder, Action<WebHostBuilderContext, ILoggingBuilder> configureLogging)
		{
			throw null;
		}

		public static IWebHostBuilder ConfigureLogging(this IWebHostBuilder hostBuilder, Action<ILoggingBuilder> configureLogging)
		{
			throw null;
		}

		public static IWebHostBuilder UseDefaultServiceProvider(this IWebHostBuilder hostBuilder, Action<WebHostBuilderContext, ServiceProviderOptions> configure)
		{
			throw null;
		}

		public static IWebHostBuilder UseDefaultServiceProvider(this IWebHostBuilder hostBuilder, Action<ServiceProviderOptions> configure)
		{
			throw null;
		}

		public static IWebHostBuilder UseStartup(this IWebHostBuilder hostBuilder, Type startupType)
		{
			throw null;
		}

		public static IWebHostBuilder UseStartup<TStartup>(this IWebHostBuilder hostBuilder) where TStartup : class
		{
			throw null;
		}

		public static IWebHostBuilder UseStaticWebAssets(this IWebHostBuilder builder)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\WebHostExtensions.cs
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Hosting
{
	public static class WebHostExtensions
	{
		public static void Run(this IWebHost host)
		{
		}

		[DebuggerStepThrough]
		public static Task RunAsync(this IWebHost host, CancellationToken token = default(CancellationToken))
		{
			throw null;
		}

		public static Task StopAsync(this IWebHost host, TimeSpan timeout)
		{
			throw null;
		}

		public static void WaitForShutdown(this IWebHost host)
		{
		}

		[DebuggerStepThrough]
		public static Task WaitForShutdownAsync(this IWebHost host, CancellationToken token = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting.Builder\ApplicationBuilderFactory.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features;
using System;

namespace Microsoft.AspNetCore.Hosting.Builder
{
	public class ApplicationBuilderFactory : IApplicationBuilderFactory
	{
		public ApplicationBuilderFactory(IServiceProvider serviceProvider)
		{
		}

		public IApplicationBuilder CreateBuilder(IFeatureCollection serverFeatures)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting.Builder\IApplicationBuilderFactory.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features;

namespace Microsoft.AspNetCore.Hosting.Builder
{
	public interface IApplicationBuilderFactory
	{
		IApplicationBuilder CreateBuilder(IFeatureCollection serverFeatures);
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting.Server.Features\ServerAddressesFeature.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Hosting.Server.Features
{
	public class ServerAddressesFeature : IServerAddressesFeature
	{
		public ICollection<string> Addresses
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool PreferHostingUrls
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting.StaticWebAssets\StaticWebAssetsLoader.cs
using Microsoft.Extensions.Configuration;
using System.IO;
using System.Reflection;

namespace Microsoft.AspNetCore.Hosting.StaticWebAssets
{
	public class StaticWebAssetsLoader
	{
		internal const string StaticWebAssetsManifestName = "Microsoft.AspNetCore.StaticWebAssets.xml";

		public static void UseStaticWebAssets(IWebHostEnvironment environment, IConfiguration configuration)
		{
		}

		internal static string GetAssemblyLocation(Assembly assembly)
		{
			throw null;
		}

		internal static Stream ResolveManifest(IWebHostEnvironment environment, IConfiguration configuration)
		{
			throw null;
		}

		internal static void UseStaticWebAssetsCore(IWebHostEnvironment environment, Stream manifest)
		{
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Http\DefaultHttpContextFactory.cs
using Microsoft.AspNetCore.Http.Features;
using System;

namespace Microsoft.AspNetCore.Http
{
	public class DefaultHttpContextFactory : IHttpContextFactory
	{
		public DefaultHttpContextFactory(IServiceProvider serviceProvider)
		{
		}

		public HttpContext Create(IFeatureCollection featureCollection)
		{
			throw null;
		}

		public void Dispose(HttpContext httpContext)
		{
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.Extensions.Hosting\GenericHostWebHostBuilderExtensions.cs
using Microsoft.AspNetCore.Hosting;
using System;

namespace Microsoft.Extensions.Hosting
{
	public static class GenericHostWebHostBuilderExtensions
	{
		public static IHostBuilder ConfigureWebHost(this IHostBuilder builder, Action<IWebHostBuilder> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\EnvironmentName.cs
using System;

namespace Microsoft.AspNetCore.Hosting
{
	[Obsolete("This type is obsolete and will be removed in a future version. The recommended alternative is Microsoft.Extensions.Hosting.Environments.", false)]
	public static class EnvironmentName
	{
		public static readonly string Development;

		public static readonly string Production;

		public static readonly string Staging;
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\HostingAbstractionsWebHostBuilderExtensions.cs
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.Configuration;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public static class HostingAbstractionsWebHostBuilderExtensions
	{
		public static IWebHostBuilder CaptureStartupErrors(this IWebHostBuilder hostBuilder, bool captureStartupErrors)
		{
			throw null;
		}

		public static IWebHostBuilder PreferHostingUrls(this IWebHostBuilder hostBuilder, bool preferHostingUrls)
		{
			throw null;
		}

		public static IWebHost Start(this IWebHostBuilder hostBuilder, params string[] urls)
		{
			throw null;
		}

		public static IWebHostBuilder SuppressStatusMessages(this IWebHostBuilder hostBuilder, bool suppressStatusMessages)
		{
			throw null;
		}

		public static IWebHostBuilder UseConfiguration(this IWebHostBuilder hostBuilder, IConfiguration configuration)
		{
			throw null;
		}

		public static IWebHostBuilder UseContentRoot(this IWebHostBuilder hostBuilder, string contentRoot)
		{
			throw null;
		}

		public static IWebHostBuilder UseEnvironment(this IWebHostBuilder hostBuilder, string environment)
		{
			throw null;
		}

		public static IWebHostBuilder UseServer(this IWebHostBuilder hostBuilder, IServer server)
		{
			throw null;
		}

		public static IWebHostBuilder UseShutdownTimeout(this IWebHostBuilder hostBuilder, TimeSpan timeout)
		{
			throw null;
		}

		public static IWebHostBuilder UseStartup(this IWebHostBuilder hostBuilder, string startupAssemblyName)
		{
			throw null;
		}

		public static IWebHostBuilder UseUrls(this IWebHostBuilder hostBuilder, params string[] urls)
		{
			throw null;
		}

		public static IWebHostBuilder UseWebRoot(this IWebHostBuilder hostBuilder, string webRoot)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\HostingEnvironmentExtensions.cs
namespace Microsoft.AspNetCore.Hosting
{
	public static class HostingEnvironmentExtensions
	{
		public static bool IsDevelopment(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}

		public static bool IsEnvironment(this IHostingEnvironment hostingEnvironment, string environmentName)
		{
			throw null;
		}

		public static bool IsProduction(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}

		public static bool IsStaging(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\HostingStartupAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Hosting
{
	[AttributeUsage(AttributeTargets.Assembly, Inherited = false, AllowMultiple = true)]
	public sealed class HostingStartupAttribute : Attribute
	{
		public Type HostingStartupType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HostingStartupAttribute(Type hostingStartupType)
		{
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IApplicationLifetime.cs
using System;
using System.Threading;

namespace Microsoft.AspNetCore.Hosting
{
	[Obsolete("This type is obsolete and will be removed in a future version. The recommended alternative is Microsoft.Extensions.Hosting.IHostApplicationLifetime.", false)]
	public interface IApplicationLifetime
	{
		CancellationToken ApplicationStarted
		{
			get;
		}

		CancellationToken ApplicationStopped
		{
			get;
		}

		CancellationToken ApplicationStopping
		{
			get;
		}

		void StopApplication();
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IHostingEnvironment.cs
using Microsoft.Extensions.FileProviders;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	[Obsolete("This type is obsolete and will be removed in a future version. The recommended alternative is Microsoft.AspNetCore.Hosting.IWebHostEnvironment.", false)]
	public interface IHostingEnvironment
	{
		string ApplicationName
		{
			get;
			set;
		}

		IFileProvider ContentRootFileProvider
		{
			get;
			set;
		}

		string ContentRootPath
		{
			get;
			set;
		}

		string EnvironmentName
		{
			get;
			set;
		}

		IFileProvider WebRootFileProvider
		{
			get;
			set;
		}

		string WebRootPath
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IHostingStartup.cs
namespace Microsoft.AspNetCore.Hosting
{
	public interface IHostingStartup
	{
		void Configure(IWebHostBuilder builder);
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IStartup.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public interface IStartup
	{
		void Configure(IApplicationBuilder app);

		IServiceProvider ConfigureServices(IServiceCollection services);
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IStartupConfigureContainerFilter.cs
using System;

namespace Microsoft.AspNetCore.Hosting
{
	[Obsolete]
	public interface IStartupConfigureContainerFilter<TContainerBuilder>
	{
		Action<TContainerBuilder> ConfigureContainer(Action<TContainerBuilder> container);
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IStartupConfigureServicesFilter.cs
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	[Obsolete]
	public interface IStartupConfigureServicesFilter
	{
		Action<IServiceCollection> ConfigureServices(Action<IServiceCollection> next);
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IStartupFilter.cs
using Microsoft.AspNetCore.Builder;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public interface IStartupFilter
	{
		Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next);
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IWebHost.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Hosting
{
	public interface IWebHost : IDisposable
	{
		IFeatureCollection ServerFeatures
		{
			get;
		}

		IServiceProvider Services
		{
			get;
		}

		void Start();

		Task StartAsync(CancellationToken cancellationToken = default(CancellationToken));

		Task StopAsync(CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IWebHostBuilder.cs
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Hosting
{
	public interface IWebHostBuilder
	{
		IWebHost Build();

		IWebHostBuilder ConfigureAppConfiguration(Action<WebHostBuilderContext, IConfigurationBuilder> configureDelegate);

		IWebHostBuilder ConfigureServices(Action<WebHostBuilderContext, IServiceCollection> configureServices);

		IWebHostBuilder ConfigureServices(Action<IServiceCollection> configureServices);

		string GetSetting(string key);

		IWebHostBuilder UseSetting(string key, string value);
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IWebHostEnvironment.cs
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace Microsoft.AspNetCore.Hosting
{
	public interface IWebHostEnvironment : IHostEnvironment
	{
		IFileProvider WebRootFileProvider
		{
			get;
			set;
		}

		string WebRootPath
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\WebHostBuilderContext.cs
using Microsoft.Extensions.Configuration;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Hosting
{
	public class WebHostBuilderContext
	{
		public IConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IWebHostEnvironment HostingEnvironment
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\WebHostDefaults.cs
namespace Microsoft.AspNetCore.Hosting
{
	public static class WebHostDefaults
	{
		public static readonly string ApplicationKey;

		public static readonly string CaptureStartupErrorsKey;

		public static readonly string ContentRootKey;

		public static readonly string DetailedErrorsKey;

		public static readonly string EnvironmentKey;

		public static readonly string HostingStartupAssembliesKey;

		public static readonly string HostingStartupExcludeAssembliesKey;

		public static readonly string PreferHostingUrlsKey;

		public static readonly string PreventHostingStartupKey;

		public static readonly string ServerUrlsKey;

		public static readonly string ShutdownTimeoutKey;

		public static readonly string StartupAssemblyKey;

		public static readonly string StaticWebAssetsKey;

		public static readonly string SuppressStatusMessagesKey;

		public static readonly string WebRootKey;
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server\IHttpApplication.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Hosting.Server
{
	public interface IHttpApplication<TContext>
	{
		TContext CreateContext(IFeatureCollection contextFeatures);

		void DisposeContext(TContext context, Exception exception);

		Task ProcessRequestAsync(TContext context);
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server\IServer.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Hosting.Server
{
	public interface IServer : IDisposable
	{
		IFeatureCollection Features
		{
			get;
		}

		Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken cancellationToken);

		Task StopAsync(CancellationToken cancellationToken);
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server\IServerIntegratedAuth.cs
namespace Microsoft.AspNetCore.Hosting.Server
{
	public interface IServerIntegratedAuth
	{
		string AuthenticationScheme
		{
			get;
		}

		bool IsEnabled
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server\ServerIntegratedAuth.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Hosting.Server
{
	public class ServerIntegratedAuth : IServerIntegratedAuth
	{
		public string AuthenticationScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool IsEnabled
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server.Abstractions\IHostContextContainer.cs
namespace Microsoft.AspNetCore.Hosting.Server.Abstractions
{
	public interface IHostContextContainer<TContext>
	{
		TContext HostContext
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server.Features\IServerAddressesFeature.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Hosting.Server.Features
{
	public interface IServerAddressesFeature
	{
		ICollection<string> Addresses
		{
			get;
		}

		bool PreferHostingUrls
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\HtmlContentBuilder.cs
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Html
{
	public class HtmlContentBuilder : IHtmlContent, IHtmlContentBuilder, IHtmlContentContainer
	{
		public int Count
		{
			get
			{
				throw null;
			}
		}

		internal IList<object> Entries
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HtmlContentBuilder()
		{
		}

		public HtmlContentBuilder(IList<object> entries)
		{
		}

		public HtmlContentBuilder(int capacity)
		{
		}

		public IHtmlContentBuilder Append(string unencoded)
		{
			throw null;
		}

		public IHtmlContentBuilder AppendHtml(IHtmlContent htmlContent)
		{
			throw null;
		}

		public IHtmlContentBuilder AppendHtml(string encoded)
		{
			throw null;
		}

		public IHtmlContentBuilder Clear()
		{
			throw null;
		}

		public void CopyTo(IHtmlContentBuilder destination)
		{
		}

		public void MoveTo(IHtmlContentBuilder destination)
		{
		}

		public void WriteTo(TextWriter writer, HtmlEncoder encoder)
		{
		}
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\HtmlContentBuilderExtensions.cs
using System;

namespace Microsoft.AspNetCore.Html
{
	public static class HtmlContentBuilderExtensions
	{
		public static IHtmlContentBuilder AppendFormat(this IHtmlContentBuilder builder, IFormatProvider formatProvider, string format, params object[] args)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendFormat(this IHtmlContentBuilder builder, string format, params object[] args)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendHtmlLine(this IHtmlContentBuilder builder, string encoded)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendLine(this IHtmlContentBuilder builder)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendLine(this IHtmlContentBuilder builder, IHtmlContent content)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendLine(this IHtmlContentBuilder builder, string unencoded)
		{
			throw null;
		}

		public static IHtmlContentBuilder SetContent(this IHtmlContentBuilder builder, string unencoded)
		{
			throw null;
		}

		public static IHtmlContentBuilder SetHtmlContent(this IHtmlContentBuilder builder, IHtmlContent content)
		{
			throw null;
		}

		public static IHtmlContentBuilder SetHtmlContent(this IHtmlContentBuilder builder, string encoded)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\HtmlFormattableString.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Html
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public class HtmlFormattableString : IHtmlContent
	{
		public HtmlFormattableString(IFormatProvider formatProvider, string format, params object[] args)
		{
		}

		public HtmlFormattableString(string format, params object[] args)
		{
		}

		public void WriteTo(TextWriter writer, HtmlEncoder encoder)
		{
		}
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\HtmlString.cs
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Html
{
	public class HtmlString : IHtmlContent
	{
		public static readonly HtmlString Empty;

		public static readonly HtmlString NewLine;

		public string Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HtmlString(string value)
		{
		}

		public override string ToString()
		{
			throw null;
		}

		public void WriteTo(TextWriter writer, HtmlEncoder encoder)
		{
		}
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\IHtmlContent.cs
using System.IO;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Html
{
	public interface IHtmlContent
	{
		void WriteTo(TextWriter writer, HtmlEncoder encoder);
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\IHtmlContentBuilder.cs
namespace Microsoft.AspNetCore.Html
{
	public interface IHtmlContentBuilder : IHtmlContent, IHtmlContentContainer
	{
		IHtmlContentBuilder Append(string unencoded);

		IHtmlContentBuilder AppendHtml(IHtmlContent content);

		IHtmlContentBuilder AppendHtml(string encoded);

		IHtmlContentBuilder Clear();
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\IHtmlContentContainer.cs
namespace Microsoft.AspNetCore.Html
{
	public interface IHtmlContentContainer : IHtmlContent
	{
		void CopyTo(IHtmlContentBuilder builder);

		void MoveTo(IHtmlContentBuilder builder);
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Builder\ApplicationBuilder.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class ApplicationBuilder : IApplicationBuilder
	{
		public IServiceProvider ApplicationServices
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IDictionary<string, object> Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IFeatureCollection ServerFeatures
		{
			get
			{
				throw null;
			}
		}

		public ApplicationBuilder(IServiceProvider serviceProvider)
		{
		}

		public ApplicationBuilder(IServiceProvider serviceProvider, object server)
		{
		}

		public RequestDelegate Build()
		{
			throw null;
		}

		public IApplicationBuilder New()
		{
			throw null;
		}

		public IApplicationBuilder Use(Func<RequestDelegate, RequestDelegate> middleware)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\BindingAddress.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class BindingAddress
	{
		public string Host
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsUnixPipe
		{
			get
			{
				throw null;
			}
		}

		public string PathBase
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int Port
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Scheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string UnixPipePath
		{
			get
			{
				throw null;
			}
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static BindingAddress Parse(string address)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\DefaultHttpContext.cs
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading;

namespace Microsoft.AspNetCore.Http
{
	public sealed class DefaultHttpContext : HttpContext
	{
		public override ConnectionInfo Connection
		{
			get
			{
				throw null;
			}
		}

		public override IFeatureCollection Features
		{
			get
			{
				throw null;
			}
		}

		public FormOptions FormOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public HttpContext HttpContext
		{
			get
			{
				throw null;
			}
		}

		public override IDictionary<object, object> Items
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public override HttpRequest Request
		{
			get
			{
				throw null;
			}
		}

		public override CancellationToken RequestAborted
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public override IServiceProvider RequestServices
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public override HttpResponse Response
		{
			get
			{
				throw null;
			}
		}

		public IServiceScopeFactory ServiceScopeFactory
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override ISession Session
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public override string TraceIdentifier
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public override ClaimsPrincipal User
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public override WebSocketManager WebSockets
		{
			get
			{
				throw null;
			}
		}

		public DefaultHttpContext()
		{
		}

		public DefaultHttpContext(IFeatureCollection features)
		{
		}

		public override void Abort()
		{
		}

		public void Initialize(IFeatureCollection features)
		{
		}

		public void Uninitialize()
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\FormCollection.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public class FormCollection : IFormCollection, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		public struct Enumerator : IEnumerator<KeyValuePair<string, StringValues>>, IEnumerator, IDisposable
		{
			private object _dummy;

			private int _dummyPrimitive;

			public KeyValuePair<string, StringValues> Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				get
				{
					throw null;
				}
			}

			public void Dispose()
			{
			}

			public bool MoveNext()
			{
				throw null;
			}

			void IEnumerator.Reset()
			{
			}
		}

		public static readonly FormCollection Empty;

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public IFormFileCollection Files
		{
			get
			{
				throw null;
			}
		}

		public StringValues this[string key]
		{
			get
			{
				throw null;
			}
		}

		public ICollection<string> Keys
		{
			get
			{
				throw null;
			}
		}

		public FormCollection(Dictionary<string, StringValues> fields, IFormFileCollection files = null)
		{
		}

		public bool ContainsKey(string key)
		{
			throw null;
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		IEnumerator<KeyValuePair<string, StringValues>> IEnumerable<KeyValuePair<string, StringValues>>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}

		public bool TryGetValue(string key, out StringValues value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\FormFile.cs
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public class FormFile : IFormFile
	{
		public string ContentDisposition
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public string ContentType
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public string FileName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IHeaderDictionary Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long Length
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FormFile(Stream baseStream, long baseStreamOffset, long length, string name, string fileName)
		{
		}

		public void CopyTo(Stream target)
		{
		}

		[DebuggerStepThrough]
		public Task CopyToAsync(Stream target, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public Stream OpenReadStream()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\FormFileCollection.cs
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public class FormFileCollection : List<IFormFile>, IFormFileCollection, IEnumerable<IFormFile>, IEnumerable, IReadOnlyCollection<IFormFile>, IReadOnlyList<IFormFile>
	{
		public IFormFile this[string name]
		{
			get
			{
				throw null;
			}
		}

		public IFormFile GetFile(string name)
		{
			throw null;
		}

		public IReadOnlyList<IFormFile> GetFiles(string name)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\HeaderDictionary.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class HeaderDictionary : IHeaderDictionary, ICollection<KeyValuePair<string, StringValues>>, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable, IDictionary<string, StringValues>
	{
		public struct Enumerator : IEnumerator<KeyValuePair<string, StringValues>>, IEnumerator, IDisposable
		{
			private object _dummy;

			private int _dummyPrimitive;

			public KeyValuePair<string, StringValues> Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				get
				{
					throw null;
				}
			}

			public void Dispose()
			{
			}

			public bool MoveNext()
			{
				throw null;
			}

			void IEnumerator.Reset()
			{
			}
		}

		public long? ContentLength
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public bool IsReadOnly
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public StringValues this[string key]
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public ICollection<string> Keys
		{
			get
			{
				throw null;
			}
		}

		StringValues IDictionary<string, StringValues>.this[string key]
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public ICollection<StringValues> Values
		{
			get
			{
				throw null;
			}
		}

		public HeaderDictionary()
		{
		}

		public HeaderDictionary(Dictionary<string, StringValues> store)
		{
		}

		public HeaderDictionary(int capacity)
		{
		}

		public void Add(KeyValuePair<string, StringValues> item)
		{
		}

		public void Add(string key, StringValues value)
		{
		}

		public void Clear()
		{
		}

		public bool Contains(KeyValuePair<string, StringValues> item)
		{
			throw null;
		}

		public bool ContainsKey(string key)
		{
			throw null;
		}

		public void CopyTo(KeyValuePair<string, StringValues>[] array, int arrayIndex)
		{
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		public bool Remove(KeyValuePair<string, StringValues> item)
		{
			throw null;
		}

		public bool Remove(string key)
		{
			throw null;
		}

		IEnumerator<KeyValuePair<string, StringValues>> IEnumerable<KeyValuePair<string, StringValues>>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}

		public bool TryGetValue(string key, out StringValues value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\HttpContextAccessor.cs
namespace Microsoft.AspNetCore.Http
{
	public class HttpContextAccessor : IHttpContextAccessor
	{
		public HttpContext HttpContext
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\HttpContextFactory.cs
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.AspNetCore.Http
{
	[Obsolete("This is obsolete and will be removed in a future version. Use DefaultHttpContextFactory instead.")]
	public class HttpContextFactory : IHttpContextFactory
	{
		public HttpContextFactory(IOptions<FormOptions> formOptions)
		{
		}

		public HttpContextFactory(IOptions<FormOptions> formOptions, IHttpContextAccessor httpContextAccessor)
		{
		}

		public HttpContextFactory(IOptions<FormOptions> formOptions, IServiceScopeFactory serviceScopeFactory)
		{
		}

		public HttpContextFactory(IOptions<FormOptions> formOptions, IServiceScopeFactory serviceScopeFactory, IHttpContextAccessor httpContextAccessor)
		{
		}

		public HttpContext Create(IFeatureCollection featureCollection)
		{
			throw null;
		}

		public void Dispose(HttpContext httpContext)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\HttpRequestRewindExtensions.cs
namespace Microsoft.AspNetCore.Http
{
	public static class HttpRequestRewindExtensions
	{
		public static void EnableBuffering(this HttpRequest request)
		{
		}

		public static void EnableBuffering(this HttpRequest request, int bufferThreshold)
		{
		}

		public static void EnableBuffering(this HttpRequest request, int bufferThreshold, long bufferLimit)
		{
		}

		public static void EnableBuffering(this HttpRequest request, long bufferLimit)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\MiddlewareFactory.cs
using System;

namespace Microsoft.AspNetCore.Http
{
	public class MiddlewareFactory : IMiddlewareFactory
	{
		public MiddlewareFactory(IServiceProvider serviceProvider)
		{
		}

		public IMiddleware Create(Type middlewareType)
		{
			throw null;
		}

		public void Release(IMiddleware middleware)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\QueryCollection.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public class QueryCollection : IQueryCollection, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		public struct Enumerator : IEnumerator<KeyValuePair<string, StringValues>>, IEnumerator, IDisposable
		{
			private object _dummy;

			private int _dummyPrimitive;

			public KeyValuePair<string, StringValues> Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				get
				{
					throw null;
				}
			}

			public void Dispose()
			{
			}

			public bool MoveNext()
			{
				throw null;
			}

			void IEnumerator.Reset()
			{
			}
		}

		public static readonly QueryCollection Empty;

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public StringValues this[string key]
		{
			get
			{
				throw null;
			}
		}

		public ICollection<string> Keys
		{
			get
			{
				throw null;
			}
		}

		public QueryCollection()
		{
		}

		public QueryCollection(QueryCollection store)
		{
		}

		public QueryCollection(Dictionary<string, StringValues> store)
		{
		}

		public QueryCollection(int capacity)
		{
		}

		public bool ContainsKey(string key)
		{
			throw null;
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		IEnumerator<KeyValuePair<string, StringValues>> IEnumerable<KeyValuePair<string, StringValues>>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}

		public bool TryGetValue(string key, out StringValues value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\RequestFormReaderExtensions.cs
using Microsoft.AspNetCore.Http.Features;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public static class RequestFormReaderExtensions
	{
		public static Task<IFormCollection> ReadFormAsync(this HttpRequest request, FormOptions options, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\SendFileFallback.cs
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public static class SendFileFallback
	{
		[DebuggerStepThrough]
		public static Task SendFileAsync(Stream destination, string filePath, long offset, long? count, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\StreamResponseBodyFeature.cs
using Microsoft.AspNetCore.Http.Features;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public class StreamResponseBodyFeature : IHttpResponseBodyFeature
	{
		public IHttpResponseBodyFeature PriorFeature
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Stream Stream
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public PipeWriter Writer
		{
			get
			{
				throw null;
			}
		}

		public StreamResponseBodyFeature(Stream stream)
		{
		}

		public StreamResponseBodyFeature(Stream stream, IHttpResponseBodyFeature priorFeature)
		{
		}

		[DebuggerStepThrough]
		public virtual Task CompleteAsync()
		{
			throw null;
		}

		public virtual void DisableBuffering()
		{
		}

		public void Dispose()
		{
		}

		[DebuggerStepThrough]
		public virtual Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task StartAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\DefaultSessionFeature.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public class DefaultSessionFeature : ISessionFeature
	{
		public ISession Session
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\FormFeature.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public class FormFeature : IFormFeature
	{
		public IFormCollection Form
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public bool HasFormContentType
		{
			get
			{
				throw null;
			}
		}

		public FormFeature(HttpRequest request)
		{
		}

		public FormFeature(HttpRequest request, FormOptions options)
		{
		}

		public FormFeature(IFormCollection form)
		{
		}

		public IFormCollection ReadForm()
		{
			throw null;
		}

		public Task<IFormCollection> ReadFormAsync()
		{
			throw null;
		}

		public Task<IFormCollection> ReadFormAsync(CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\FormOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public class FormOptions
	{
		public const int DefaultBufferBodyLengthLimit = 134217728;

		public const int DefaultMemoryBufferThreshold = 65536;

		public const long DefaultMultipartBodyLengthLimit = 134217728L;

		public const int DefaultMultipartBoundaryLengthLimit = 128;

		public bool BufferBody
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long BufferBodyLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int KeyLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int MemoryBufferThreshold
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long MultipartBodyLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int MultipartBoundaryLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int MultipartHeadersCountLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int MultipartHeadersLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int ValueCountLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int ValueLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\HttpConnectionFeature.cs
using System.Net;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public class HttpConnectionFeature : IHttpConnectionFeature
	{
		public string ConnectionId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IPAddress LocalIpAddress
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int LocalPort
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IPAddress RemoteIpAddress
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int RemotePort
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\HttpRequestFeature.cs
using System.IO;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public class HttpRequestFeature : IHttpRequestFeature
	{
		public Stream Body
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IHeaderDictionary Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Method
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string PathBase
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Protocol
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string QueryString
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string RawTarget
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Scheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\HttpRequestIdentifierFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public class HttpRequestIdentifierFeature : IHttpRequestIdentifierFeature
	{
		public string TraceIdentifier
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\HttpRequestLifetimeFeature.cs
using System.Runtime.CompilerServices;
using System.Threading;

namespace Microsoft.AspNetCore.Http.Features
{
	public class HttpRequestLifetimeFeature : IHttpRequestLifetimeFeature
	{
		public CancellationToken RequestAborted
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public void Abort()
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\HttpResponseFeature.cs
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public class HttpResponseFeature : IHttpResponseFeature
	{
		public Stream Body
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual bool HasStarted
		{
			get
			{
				throw null;
			}
		}

		public IHeaderDictionary Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ReasonPhrase
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int StatusCode
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual void OnCompleted(Func<object, Task> callback, object state)
		{
		}

		public virtual void OnStarting(Func<object, Task> callback, object state)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\ItemsFeature.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public class ItemsFeature : IItemsFeature
	{
		public IDictionary<object, object> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\QueryFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public class QueryFeature : IQueryFeature
	{
		public IQueryCollection Query
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public QueryFeature(IFeatureCollection features)
		{
		}

		public QueryFeature(IQueryCollection query)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\RequestBodyPipeFeature.cs
using System.IO.Pipelines;

namespace Microsoft.AspNetCore.Http.Features
{
	public class RequestBodyPipeFeature : IRequestBodyPipeFeature
	{
		public PipeReader Reader
		{
			get
			{
				throw null;
			}
		}

		public RequestBodyPipeFeature(HttpContext context)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\RequestCookiesFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public class RequestCookiesFeature : IRequestCookiesFeature
	{
		public IRequestCookieCollection Cookies
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public RequestCookiesFeature(IFeatureCollection features)
		{
		}

		public RequestCookiesFeature(IRequestCookieCollection cookies)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\RequestServicesFeature.cs
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public class RequestServicesFeature : IServiceProvidersFeature, IAsyncDisposable, IDisposable
	{
		public IServiceProvider RequestServices
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public RequestServicesFeature(HttpContext context, IServiceScopeFactory scopeFactory)
		{
		}

		public void Dispose()
		{
		}

		public ValueTask DisposeAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\ResponseCookiesFeature.cs
using Microsoft.Extensions.ObjectPool;
using System.Text;

namespace Microsoft.AspNetCore.Http.Features
{
	public class ResponseCookiesFeature : IResponseCookiesFeature
	{
		public IResponseCookies Cookies
		{
			get
			{
				throw null;
			}
		}

		public ResponseCookiesFeature(IFeatureCollection features)
		{
		}

		public ResponseCookiesFeature(IFeatureCollection features, ObjectPool<StringBuilder> builderPool)
		{
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\RouteValuesFeature.cs
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Http.Features
{
	public class RouteValuesFeature : IRouteValuesFeature
	{
		public RouteValueDictionary RouteValues
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\ServiceProvidersFeature.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public class ServiceProvidersFeature : IServiceProvidersFeature
	{
		public IServiceProvider RequestServices
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\TlsConnectionFeature.cs
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public class TlsConnectionFeature : ITlsConnectionFeature
	{
		public X509Certificate2 ClientCertificate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Task<X509Certificate2> GetClientCertificateAsync(CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features.Authentication\HttpAuthenticationFeature.cs
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Http.Features.Authentication
{
	public class HttpAuthenticationFeature : IHttpAuthenticationFeature
	{
		public ClaimsPrincipal User
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.Extensions.DependencyInjection\HttpServiceCollectionExtensions.cs
namespace Microsoft.Extensions.DependencyInjection
{
	public static class HttpServiceCollectionExtensions
	{
		public static IServiceCollection AddHttpContextAccessor(this IServiceCollection services)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\EndpointBuilder.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public abstract class EndpointBuilder
	{
		public string DisplayName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<object> Metadata
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RequestDelegate RequestDelegate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public abstract Endpoint Build();
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\IApplicationBuilder.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Builder
{
	public interface IApplicationBuilder
	{
		IServiceProvider ApplicationServices
		{
			get;
			set;
		}

		IDictionary<string, object> Properties
		{
			get;
		}

		IFeatureCollection ServerFeatures
		{
			get;
		}

		RequestDelegate Build();

		IApplicationBuilder New();

		IApplicationBuilder Use(Func<RequestDelegate, RequestDelegate> middleware);
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\IEndpointConventionBuilder.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public interface IEndpointConventionBuilder
	{
		void Add(Action<EndpointBuilder> convention);
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\MapExtensions.cs
using Microsoft.AspNetCore.Http;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class MapExtensions
	{
		public static IApplicationBuilder Map(this IApplicationBuilder app, PathString pathMatch, Action<IApplicationBuilder> configuration)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\MapWhenExtensions.cs
using Microsoft.AspNetCore.Http;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class MapWhenExtensions
	{
		public static IApplicationBuilder MapWhen(this IApplicationBuilder app, Func<HttpContext, bool> predicate, Action<IApplicationBuilder> configuration)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\RunExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Builder
{
	public static class RunExtensions
	{
		public static void Run(this IApplicationBuilder app, RequestDelegate handler)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\UseExtensions.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder
{
	public static class UseExtensions
	{
		public static IApplicationBuilder Use(this IApplicationBuilder app, Func<HttpContext, Func<Task>, Task> middleware)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\UseMiddlewareExtensions.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class UseMiddlewareExtensions
	{
		internal const string InvokeAsyncMethodName = "InvokeAsync";

		internal const string InvokeMethodName = "Invoke";

		public static IApplicationBuilder UseMiddleware(this IApplicationBuilder app, Type middleware, params object[] args)
		{
			throw null;
		}

		public static IApplicationBuilder UseMiddleware<TMiddleware>(this IApplicationBuilder app, params object[] args)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\UsePathBaseExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Builder
{
	public static class UsePathBaseExtensions
	{
		public static IApplicationBuilder UsePathBase(this IApplicationBuilder app, PathString pathBase)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder\UseWhenExtensions.cs
using Microsoft.AspNetCore.Http;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class UseWhenExtensions
	{
		public static IApplicationBuilder UseWhen(this IApplicationBuilder app, Func<HttpContext, bool> predicate, Action<IApplicationBuilder> configuration)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder.Extensions\MapMiddleware.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class MapMiddleware
	{
		public MapMiddleware(RequestDelegate next, MapOptions options)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder.Extensions\MapOptions.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class MapOptions
	{
		public RequestDelegate Branch
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public PathString PathMatch
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder.Extensions\MapWhenMiddleware.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class MapWhenMiddleware
	{
		public MapWhenMiddleware(RequestDelegate next, MapWhenOptions options)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder.Extensions\MapWhenOptions.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class MapWhenOptions
	{
		public RequestDelegate Branch
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Func<HttpContext, bool> Predicate
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder.Extensions\UsePathBaseMiddleware.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class UsePathBaseMiddleware
	{
		public UsePathBaseMiddleware(RequestDelegate next, PathString pathBase)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Cors.Infrastructure\ICorsMetadata.cs
namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public interface ICorsMetadata
	{
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\ConnectionInfo.cs
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public abstract class ConnectionInfo
	{
		public abstract X509Certificate2 ClientCertificate
		{
			get;
			set;
		}

		public abstract string Id
		{
			get;
			set;
		}

		public abstract IPAddress LocalIpAddress
		{
			get;
			set;
		}

		public abstract int LocalPort
		{
			get;
			set;
		}

		public abstract IPAddress RemoteIpAddress
		{
			get;
			set;
		}

		public abstract int RemotePort
		{
			get;
			set;
		}

		public abstract Task<X509Certificate2> GetClientCertificateAsync(CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\CookieBuilder.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class CookieBuilder
	{
		public virtual string Domain
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual TimeSpan? Expiration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual bool HttpOnly
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual bool IsEssential
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual TimeSpan? MaxAge
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual string Name
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public virtual string Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual SameSiteMode SameSite
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual CookieSecurePolicy SecurePolicy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookieOptions Build(HttpContext context)
		{
			throw null;
		}

		public virtual CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\CookieSecurePolicy.cs
namespace Microsoft.AspNetCore.Http
{
	public enum CookieSecurePolicy
	{
		SameAsRequest,
		Always,
		None
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\Endpoint.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class Endpoint
	{
		public string DisplayName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public EndpointMetadataCollection Metadata
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RequestDelegate RequestDelegate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Endpoint(RequestDelegate requestDelegate, EndpointMetadataCollection metadata, string displayName)
		{
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\EndpointHttpContextExtensions.cs
namespace Microsoft.AspNetCore.Http
{
	public static class EndpointHttpContextExtensions
	{
		public static Endpoint GetEndpoint(this HttpContext context)
		{
			throw null;
		}

		public static void SetEndpoint(this HttpContext context, Endpoint endpoint)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\EndpointMetadataCollection.cs
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public sealed class EndpointMetadataCollection : IEnumerable<object>, IEnumerable, IReadOnlyCollection<object>, IReadOnlyList<object>
	{
		public struct Enumerator : IEnumerator<object>, IEnumerator, IDisposable
		{
			private object _dummy;

			private int _dummyPrimitive;

			public object Current
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public void Dispose()
			{
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Reset()
			{
			}
		}

		public static readonly EndpointMetadataCollection Empty;

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public object this[int index]
		{
			get
			{
				throw null;
			}
		}

		public EndpointMetadataCollection(IEnumerable<object> items)
		{
		}

		public EndpointMetadataCollection(params object[] items)
		{
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public T GetMetadata<T>() where T : class
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public IReadOnlyList<T> GetOrderedMetadata<T>() where T : class
		{
			throw null;
		}

		IEnumerator<object> IEnumerable<object>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\FragmentString.cs
using System;

namespace Microsoft.AspNetCore.Http
{
	public readonly struct FragmentString : IEquatable<FragmentString>
	{
		private readonly object _dummy;

		public static readonly FragmentString Empty;

		public bool HasValue
		{
			get
			{
				throw null;
			}
		}

		public string Value
		{
			get
			{
				throw null;
			}
		}

		public FragmentString(string value)
		{
			throw null;
		}

		public bool Equals(FragmentString other)
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public static FragmentString FromUriComponent(string uriComponent)
		{
			throw null;
		}

		public static FragmentString FromUriComponent(Uri uri)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static bool operator ==(FragmentString left, FragmentString right)
		{
			throw null;
		}

		public static bool operator !=(FragmentString left, FragmentString right)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}

		public string ToUriComponent()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HeaderDictionaryExtensions.cs
using Microsoft.Extensions.Primitives;

namespace Microsoft.AspNetCore.Http
{
	public static class HeaderDictionaryExtensions
	{
		public static void Append(this IHeaderDictionary headers, string key, StringValues value)
		{
		}

		public static void AppendCommaSeparatedValues(this IHeaderDictionary headers, string key, params string[] values)
		{
		}

		public static string[] GetCommaSeparatedValues(this IHeaderDictionary headers, string key)
		{
			throw null;
		}

		public static void SetCommaSeparatedValues(this IHeaderDictionary headers, string key, params string[] values)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HostString.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public readonly struct HostString : IEquatable<HostString>
	{
		private readonly object _dummy;

		public bool HasValue
		{
			get
			{
				throw null;
			}
		}

		public string Host
		{
			get
			{
				throw null;
			}
		}

		public int? Port
		{
			get
			{
				throw null;
			}
		}

		public string Value
		{
			get
			{
				throw null;
			}
		}

		public HostString(string value)
		{
			throw null;
		}

		public HostString(string host, int port)
		{
			throw null;
		}

		public bool Equals(HostString other)
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public static HostString FromUriComponent(string uriComponent)
		{
			throw null;
		}

		public static HostString FromUriComponent(Uri uri)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static bool MatchesAny(StringSegment value, IList<StringSegment> patterns)
		{
			throw null;
		}

		public static bool operator ==(HostString left, HostString right)
		{
			throw null;
		}

		public static bool operator !=(HostString left, HostString right)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}

		public string ToUriComponent()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HttpContext.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;

namespace Microsoft.AspNetCore.Http
{
	public abstract class HttpContext
	{
		public abstract ConnectionInfo Connection
		{
			get;
		}

		public abstract IFeatureCollection Features
		{
			get;
		}

		public abstract IDictionary<object, object> Items
		{
			get;
			set;
		}

		public abstract HttpRequest Request
		{
			get;
		}

		public abstract CancellationToken RequestAborted
		{
			get;
			set;
		}

		public abstract IServiceProvider RequestServices
		{
			get;
			set;
		}

		public abstract HttpResponse Response
		{
			get;
		}

		public abstract ISession Session
		{
			get;
			set;
		}

		public abstract string TraceIdentifier
		{
			get;
			set;
		}

		public abstract ClaimsPrincipal User
		{
			get;
			set;
		}

		public abstract WebSocketManager WebSockets
		{
			get;
		}

		public abstract void Abort();
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HttpMethods.cs
namespace Microsoft.AspNetCore.Http
{
	public static class HttpMethods
	{
		public static readonly string Connect;

		public static readonly string Delete;

		public static readonly string Get;

		public static readonly string Head;

		public static readonly string Options;

		public static readonly string Patch;

		public static readonly string Post;

		public static readonly string Put;

		public static readonly string Trace;

		public static bool IsConnect(string method)
		{
			throw null;
		}

		public static bool IsDelete(string method)
		{
			throw null;
		}

		public static bool IsGet(string method)
		{
			throw null;
		}

		public static bool IsHead(string method)
		{
			throw null;
		}

		public static bool IsOptions(string method)
		{
			throw null;
		}

		public static bool IsPatch(string method)
		{
			throw null;
		}

		public static bool IsPost(string method)
		{
			throw null;
		}

		public static bool IsPut(string method)
		{
			throw null;
		}

		public static bool IsTrace(string method)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HttpRequest.cs
using Microsoft.AspNetCore.Routing;
using System.IO;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public abstract class HttpRequest
	{
		public abstract Stream Body
		{
			get;
			set;
		}

		public virtual PipeReader BodyReader
		{
			get
			{
				throw null;
			}
		}

		public abstract long? ContentLength
		{
			get;
			set;
		}

		public abstract string ContentType
		{
			get;
			set;
		}

		public abstract IRequestCookieCollection Cookies
		{
			get;
			set;
		}

		public abstract IFormCollection Form
		{
			get;
			set;
		}

		public abstract bool HasFormContentType
		{
			get;
		}

		public abstract IHeaderDictionary Headers
		{
			get;
		}

		public abstract HostString Host
		{
			get;
			set;
		}

		public abstract HttpContext HttpContext
		{
			get;
		}

		public abstract bool IsHttps
		{
			get;
			set;
		}

		public abstract string Method
		{
			get;
			set;
		}

		public abstract PathString Path
		{
			get;
			set;
		}

		public abstract PathString PathBase
		{
			get;
			set;
		}

		public abstract string Protocol
		{
			get;
			set;
		}

		public abstract IQueryCollection Query
		{
			get;
			set;
		}

		public abstract QueryString QueryString
		{
			get;
			set;
		}

		public virtual RouteValueDictionary RouteValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public abstract string Scheme
		{
			get;
			set;
		}

		public abstract Task<IFormCollection> ReadFormAsync(CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HttpResponse.cs
using System;
using System.IO;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public abstract class HttpResponse
	{
		public abstract Stream Body
		{
			get;
			set;
		}

		public virtual PipeWriter BodyWriter
		{
			get
			{
				throw null;
			}
		}

		public abstract long? ContentLength
		{
			get;
			set;
		}

		public abstract string ContentType
		{
			get;
			set;
		}

		public abstract IResponseCookies Cookies
		{
			get;
		}

		public abstract bool HasStarted
		{
			get;
		}

		public abstract IHeaderDictionary Headers
		{
			get;
		}

		public abstract HttpContext HttpContext
		{
			get;
		}

		public abstract int StatusCode
		{
			get;
			set;
		}

		public virtual Task CompleteAsync()
		{
			throw null;
		}

		public abstract void OnCompleted(Func<object, Task> callback, object state);

		public virtual void OnCompleted(Func<Task> callback)
		{
		}

		public abstract void OnStarting(Func<object, Task> callback, object state);

		public virtual void OnStarting(Func<Task> callback)
		{
		}

		public virtual void Redirect(string location)
		{
		}

		public abstract void Redirect(string location, bool permanent);

		public virtual void RegisterForDispose(IDisposable disposable)
		{
		}

		public virtual void RegisterForDisposeAsync(IAsyncDisposable disposable)
		{
		}

		public virtual Task StartAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HttpResponseWritingExtensions.cs
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public static class HttpResponseWritingExtensions
	{
		public static Task WriteAsync(this HttpResponse response, string text, Encoding encoding, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task WriteAsync(this HttpResponse response, string text, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\IHttpContextAccessor.cs
namespace Microsoft.AspNetCore.Http
{
	public interface IHttpContextAccessor
	{
		HttpContext HttpContext
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\IHttpContextFactory.cs
using Microsoft.AspNetCore.Http.Features;

namespace Microsoft.AspNetCore.Http
{
	public interface IHttpContextFactory
	{
		HttpContext Create(IFeatureCollection featureCollection);

		void Dispose(HttpContext httpContext);
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\IMiddleware.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public interface IMiddleware
	{
		Task InvokeAsync(HttpContext context, RequestDelegate next);
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\IMiddlewareFactory.cs
using System;

namespace Microsoft.AspNetCore.Http
{
	public interface IMiddlewareFactory
	{
		IMiddleware Create(Type middlewareType);

		void Release(IMiddleware middleware);
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\PathString.cs
using System;

namespace Microsoft.AspNetCore.Http
{
	public readonly struct PathString : IEquatable<PathString>
	{
		private readonly object _dummy;

		public static readonly PathString Empty;

		public bool HasValue
		{
			get
			{
				throw null;
			}
		}

		public string Value
		{
			get
			{
				throw null;
			}
		}

		public PathString(string value)
		{
			throw null;
		}

		public PathString Add(PathString other)
		{
			throw null;
		}

		public string Add(QueryString other)
		{
			throw null;
		}

		public bool Equals(PathString other)
		{
			throw null;
		}

		public bool Equals(PathString other, StringComparison comparisonType)
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public static PathString FromUriComponent(string uriComponent)
		{
			throw null;
		}

		public static PathString FromUriComponent(Uri uri)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static PathString operator +(PathString left, PathString right)
		{
			throw null;
		}

		public static string operator +(PathString left, QueryString right)
		{
			throw null;
		}

		public static string operator +(PathString left, string right)
		{
			throw null;
		}

		public static string operator +(string left, PathString right)
		{
			throw null;
		}

		public static bool operator ==(PathString left, PathString right)
		{
			throw null;
		}

		public static implicit operator string(PathString path)
		{
			throw null;
		}

		public static implicit operator PathString(string s)
		{
			throw null;
		}

		public static bool operator !=(PathString left, PathString right)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, out PathString remaining)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, out PathString matched, out PathString remaining)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, StringComparison comparisonType)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, StringComparison comparisonType, out PathString remaining)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, StringComparison comparisonType, out PathString matched, out PathString remaining)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}

		public string ToUriComponent()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\QueryString.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public readonly struct QueryString : IEquatable<QueryString>
	{
		private readonly object _dummy;

		public static readonly QueryString Empty;

		public bool HasValue
		{
			get
			{
				throw null;
			}
		}

		public string Value
		{
			get
			{
				throw null;
			}
		}

		public QueryString(string value)
		{
			throw null;
		}

		public QueryString Add(QueryString other)
		{
			throw null;
		}

		public QueryString Add(string name, string value)
		{
			throw null;
		}

		public static QueryString Create(IEnumerable<KeyValuePair<string, StringValues>> parameters)
		{
			throw null;
		}

		public static QueryString Create(IEnumerable<KeyValuePair<string, string>> parameters)
		{
			throw null;
		}

		public static QueryString Create(string name, string value)
		{
			throw null;
		}

		public bool Equals(QueryString other)
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public static QueryString FromUriComponent(string uriComponent)
		{
			throw null;
		}

		public static QueryString FromUriComponent(Uri uri)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static QueryString operator +(QueryString left, QueryString right)
		{
			throw null;
		}

		public static bool operator ==(QueryString left, QueryString right)
		{
			throw null;
		}

		public static bool operator !=(QueryString left, QueryString right)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}

		public string ToUriComponent()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\RequestDelegate.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public delegate Task RequestDelegate(HttpContext context);
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\RequestTrailerExtensions.cs
using Microsoft.Extensions.Primitives;

namespace Microsoft.AspNetCore.Http
{
	public static class RequestTrailerExtensions
	{
		public static bool CheckTrailersAvailable(this HttpRequest request)
		{
			throw null;
		}

		public static StringValues GetDeclaredTrailers(this HttpRequest request)
		{
			throw null;
		}

		public static StringValues GetTrailer(this HttpRequest request, string trailerName)
		{
			throw null;
		}

		public static bool SupportsTrailers(this HttpRequest request)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\ResponseTrailerExtensions.cs
using Microsoft.Extensions.Primitives;

namespace Microsoft.AspNetCore.Http
{
	public static class ResponseTrailerExtensions
	{
		public static void AppendTrailer(this HttpResponse response, string trailerName, StringValues trailerValues)
		{
		}

		public static void DeclareTrailer(this HttpResponse response, string trailerName)
		{
		}

		public static bool SupportsTrailers(this HttpResponse response)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\StatusCodes.cs
namespace Microsoft.AspNetCore.Http
{
	public static class StatusCodes
	{
		public const int Status100Continue = 100;

		public const int Status101SwitchingProtocols = 101;

		public const int Status102Processing = 102;

		public const int Status200OK = 200;

		public const int Status201Created = 201;

		public const int Status202Accepted = 202;

		public const int Status203NonAuthoritative = 203;

		public const int Status204NoContent = 204;

		public const int Status205ResetContent = 205;

		public const int Status206PartialContent = 206;

		public const int Status207MultiStatus = 207;

		public const int Status208AlreadyReported = 208;

		public const int Status226IMUsed = 226;

		public const int Status300MultipleChoices = 300;

		public const int Status301MovedPermanently = 301;

		public const int Status302Found = 302;

		public const int Status303SeeOther = 303;

		public const int Status304NotModified = 304;

		public const int Status305UseProxy = 305;

		public const int Status306SwitchProxy = 306;

		public const int Status307TemporaryRedirect = 307;

		public const int Status308PermanentRedirect = 308;

		public const int Status400BadRequest = 400;

		public const int Status401Unauthorized = 401;

		public const int Status402PaymentRequired = 402;

		public const int Status403Forbidden = 403;

		public const int Status404NotFound = 404;

		public const int Status405MethodNotAllowed = 405;

		public const int Status406NotAcceptable = 406;

		public const int Status407ProxyAuthenticationRequired = 407;

		public const int Status408RequestTimeout = 408;

		public const int Status409Conflict = 409;

		public const int Status410Gone = 410;

		public const int Status411LengthRequired = 411;

		public const int Status412PreconditionFailed = 412;

		public const int Status413PayloadTooLarge = 413;

		public const int Status413RequestEntityTooLarge = 413;

		public const int Status414RequestUriTooLong = 414;

		public const int Status414UriTooLong = 414;

		public const int Status415UnsupportedMediaType = 415;

		public const int Status416RangeNotSatisfiable = 416;

		public const int Status416RequestedRangeNotSatisfiable = 416;

		public const int Status417ExpectationFailed = 417;

		public const int Status418ImATeapot = 418;

		public const int Status419AuthenticationTimeout = 419;

		public const int Status421MisdirectedRequest = 421;

		public const int Status422UnprocessableEntity = 422;

		public const int Status423Locked = 423;

		public const int Status424FailedDependency = 424;

		public const int Status426UpgradeRequired = 426;

		public const int Status428PreconditionRequired = 428;

		public const int Status429TooManyRequests = 429;

		public const int Status431RequestHeaderFieldsTooLarge = 431;

		public const int Status451UnavailableForLegalReasons = 451;

		public const int Status500InternalServerError = 500;

		public const int Status501NotImplemented = 501;

		public const int Status502BadGateway = 502;

		public const int Status503ServiceUnavailable = 503;

		public const int Status504GatewayTimeout = 504;

		public const int Status505HttpVersionNotsupported = 505;

		public const int Status506VariantAlsoNegotiates = 506;

		public const int Status507InsufficientStorage = 507;

		public const int Status508LoopDetected = 508;

		public const int Status510NotExtended = 510;

		public const int Status511NetworkAuthenticationRequired = 511;
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\WebSocketManager.cs
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public abstract class WebSocketManager
	{
		public abstract bool IsWebSocketRequest
		{
			get;
		}

		public abstract IList<string> WebSocketRequestedProtocols
		{
			get;
		}

		public virtual Task<WebSocket> AcceptWebSocketAsync()
		{
			throw null;
		}

		public abstract Task<WebSocket> AcceptWebSocketAsync(string subProtocol);
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http.Features\IEndpointFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IEndpointFeature
	{
		Endpoint Endpoint
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http.Features\IRouteValuesFeature.cs
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IRouteValuesFeature
	{
		RouteValueDictionary RouteValues
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.Extensions.Internal\ObjectFactory.cs
using System;

namespace Microsoft.Extensions.Internal
{
	internal delegate object ObjectFactory(IServiceProvider serviceProvider, object[] arguments);
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Builder\ConnectionEndpointRouteBuilder.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public sealed class ConnectionEndpointRouteBuilder : IEndpointConventionBuilder
	{
		internal ConnectionEndpointRouteBuilder()
		{
		}

		public void Add(Action<EndpointBuilder> convention)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Builder\ConnectionEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Routing;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class ConnectionEndpointRouteBuilderExtensions
	{
		public static ConnectionEndpointRouteBuilder MapConnectionHandler<TConnectionHandler>(this IEndpointRouteBuilder endpoints, string pattern) where TConnectionHandler : ConnectionHandler
		{
			throw null;
		}

		public static ConnectionEndpointRouteBuilder MapConnectionHandler<TConnectionHandler>(this IEndpointRouteBuilder endpoints, string pattern, Action<HttpConnectionDispatcherOptions> configureOptions) where TConnectionHandler : ConnectionHandler
		{
			throw null;
		}

		public static ConnectionEndpointRouteBuilder MapConnections(this IEndpointRouteBuilder endpoints, string pattern, HttpConnectionDispatcherOptions options, Action<IConnectionBuilder> configure)
		{
			throw null;
		}

		public static ConnectionEndpointRouteBuilder MapConnections(this IEndpointRouteBuilder endpoints, string pattern, Action<IConnectionBuilder> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Builder\ConnectionsAppBuilderExtensions.cs
using Microsoft.AspNetCore.Http.Connections;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class ConnectionsAppBuilderExtensions
	{
		[Obsolete("This method is obsolete and will be removed in a future version. The recommended alternative is to use MapConnections or MapConnectionHandler<TConnectionHandler> inside Microsoft.AspNetCore.Builder.UseEndpoints(...).")]
		public static IApplicationBuilder UseConnections(this IApplicationBuilder app, Action<ConnectionsRouteBuilder> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\ConnectionOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Connections
{
	public class ConnectionOptions
	{
		public TimeSpan? DisconnectTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\ConnectionOptionsSetup.cs
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.AspNetCore.Http.Connections
{
	public class ConnectionOptionsSetup : IConfigureOptions<ConnectionOptions>
	{
		public static TimeSpan DefaultDisconectTimeout;

		public void Configure(ConnectionOptions options)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\ConnectionsRouteBuilder.cs
using Microsoft.AspNetCore.Connections;
using System;

namespace Microsoft.AspNetCore.Http.Connections
{
	[Obsolete("This class is obsolete and will be removed in a future version. The recommended alternative is to use MapConnection and MapConnectionHandler<TConnectionHandler> inside Microsoft.AspNetCore.Builder.UseEndpoints(...).")]
	public class ConnectionsRouteBuilder
	{
		internal ConnectionsRouteBuilder()
		{
		}

		public void MapConnectionHandler<TConnectionHandler>(PathString path) where TConnectionHandler : ConnectionHandler
		{
		}

		public void MapConnectionHandler<TConnectionHandler>(PathString path, Action<HttpConnectionDispatcherOptions> configureOptions) where TConnectionHandler : ConnectionHandler
		{
		}

		public void MapConnections(PathString path, HttpConnectionDispatcherOptions options, Action<IConnectionBuilder> configure)
		{
		}

		public void MapConnections(PathString path, Action<IConnectionBuilder> configure)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\HttpConnectionContextExtensions.cs
using Microsoft.AspNetCore.Connections;

namespace Microsoft.AspNetCore.Http.Connections
{
	public static class HttpConnectionContextExtensions
	{
		public static HttpContext GetHttpContext(this ConnectionContext connection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\HttpConnectionDispatcherOptions.cs
using Microsoft.AspNetCore.Authorization;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Connections
{
	public class HttpConnectionDispatcherOptions
	{
		public long ApplicationMaxBufferSize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<IAuthorizeData> AuthorizationData
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LongPollingOptions LongPolling
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int MinimumProtocolVersion
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long TransportMaxBufferSize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public HttpTransportType Transports
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public WebSocketOptions WebSockets
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HttpConnectionDispatcherOptions()
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\LongPollingOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Connections
{
	public class LongPollingOptions
	{
		public TimeSpan PollTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\NegotiateMetadata.cs
namespace Microsoft.AspNetCore.Http.Connections
{
	public class NegotiateMetadata
	{
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\WebSocketOptions.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Connections
{
	public class WebSocketOptions
	{
		public TimeSpan CloseTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Func<IList<string>, string> SubProtocolSelector
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections.Features\IHttpContextFeature.cs
namespace Microsoft.AspNetCore.Http.Connections.Features
{
	public interface IHttpContextFeature
	{
		HttpContext HttpContext
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections.Features\IHttpTransportFeature.cs
namespace Microsoft.AspNetCore.Http.Connections.Features
{
	public interface IHttpTransportFeature
	{
		HttpTransportType TransportType
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.Extensions.DependencyInjection\ConnectionsDependencyInjectionExtensions.cs
using Microsoft.AspNetCore.Http.Connections;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class ConnectionsDependencyInjectionExtensions
	{
		public static IServiceCollection AddConnections(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddConnections(this IServiceCollection services, Action<ConnectionOptions> options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.Extensions.Internal\ValueStopwatch.cs
using System;
using System.Diagnostics;

namespace Microsoft.Extensions.Internal
{
	internal struct ValueStopwatch
	{
		private static readonly double TimestampToTicks = 10000000.0 / (double)Stopwatch.Frequency;

		private long _startTimestamp;

		public bool IsActive => _startTimestamp != 0;

		private ValueStopwatch(long startTimestamp)
		{
			_startTimestamp = startTimestamp;
		}

		public static ValueStopwatch StartNew()
		{
			return new ValueStopwatch(Stopwatch.GetTimestamp());
		}

		public TimeSpan GetElapsedTime()
		{
			if (!IsActive)
			{
				throw new InvalidOperationException("An uninitialized, or 'default', ValueStopwatch cannot be used to get elapsed time.");
			}
			long num = Stopwatch.GetTimestamp() - _startTimestamp;
			return new TimeSpan((long)(TimestampToTicks * (double)num));
		}
	}
}


// Microsoft.AspNetCore.Http.Connections.Common\Microsoft.AspNetCore.Http.Connections\AvailableTransport.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Connections
{
	public class AvailableTransport
	{
		public IList<string> TransferFormats
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Transport
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Connections.Common\Microsoft.AspNetCore.Http.Connections\HttpTransports.cs
namespace Microsoft.AspNetCore.Http.Connections
{
	public static class HttpTransports
	{
		public static readonly HttpTransportType All;
	}
}


// Microsoft.AspNetCore.Http.Connections.Common\Microsoft.AspNetCore.Http.Connections\HttpTransportType.cs
using System;

namespace Microsoft.AspNetCore.Http.Connections
{
	[Flags]
	public enum HttpTransportType
	{
		None = 0x0,
		WebSockets = 0x1,
		ServerSentEvents = 0x2,
		LongPolling = 0x4
	}
}


// Microsoft.AspNetCore.Http.Connections.Common\Microsoft.AspNetCore.Http.Connections\NegotiateProtocol.cs
using System;
using System.Buffers;
using System.IO;

namespace Microsoft.AspNetCore.Http.Connections
{
	public static class NegotiateProtocol
	{
		[Obsolete("This method is obsolete and will be removed in a future version. The recommended alternative is ParseResponse(ReadOnlySpan{byte}).")]
		public static NegotiationResponse ParseResponse(Stream content)
		{
			throw null;
		}

		public static NegotiationResponse ParseResponse(ReadOnlySpan<byte> content)
		{
			throw null;
		}

		public static void WriteResponse(NegotiationResponse response, IBufferWriter<byte> output)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Connections.Common\Microsoft.AspNetCore.Http.Connections\NegotiationResponse.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Connections
{
	public class NegotiationResponse
	{
		public string AccessToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<AvailableTransport> AvailableTransports
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ConnectionId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ConnectionToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Url
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int Version
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\HeaderDictionaryTypeExtensions.cs
using Microsoft.AspNetCore.Http.Headers;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public static class HeaderDictionaryTypeExtensions
	{
		public static void AppendList<T>(this IHeaderDictionary Headers, string name, IList<T> values)
		{
		}

		public static RequestHeaders GetTypedHeaders(this HttpRequest request)
		{
			throw null;
		}

		public static ResponseHeaders GetTypedHeaders(this HttpResponse response)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\HttpContextServerVariableExtensions.cs
namespace Microsoft.AspNetCore.Http
{
	public static class HttpContextServerVariableExtensions
	{
		public static string GetServerVariable(this HttpContext context, string variableName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\ResponseExtensions.cs
namespace Microsoft.AspNetCore.Http
{
	public static class ResponseExtensions
	{
		public static void Clear(this HttpResponse response)
		{
		}

		public static void Redirect(this HttpResponse response, string location, bool permanent, bool preserveMethod)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\SendFileResponseExtensions.cs
using Microsoft.Extensions.FileProviders;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public static class SendFileResponseExtensions
	{
		public static Task SendFileAsync(this HttpResponse response, IFileInfo file, long offset, long? count, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendFileAsync(this HttpResponse response, IFileInfo file, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendFileAsync(this HttpResponse response, string fileName, long offset, long? count, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendFileAsync(this HttpResponse response, string fileName, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\SessionExtensions.cs
namespace Microsoft.AspNetCore.Http
{
	public static class SessionExtensions
	{
		public static byte[] Get(this ISession session, string key)
		{
			throw null;
		}

		public static int? GetInt32(this ISession session, string key)
		{
			throw null;
		}

		public static string GetString(this ISession session, string key)
		{
			throw null;
		}

		public static void SetInt32(this ISession session, string key, int value)
		{
		}

		public static void SetString(this ISession session, string key, string value)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http.Extensions\HttpRequestMultipartExtensions.cs
namespace Microsoft.AspNetCore.Http.Extensions
{
	public static class HttpRequestMultipartExtensions
	{
		public static string GetMultipartBoundary(this HttpRequest request)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http.Extensions\QueryBuilder.cs
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http.Extensions
{
	public class QueryBuilder : IEnumerable<KeyValuePair<string, string>>, IEnumerable
	{
		public QueryBuilder()
		{
		}

		public QueryBuilder(IEnumerable<KeyValuePair<string, string>> parameters)
		{
		}

		public void Add(string key, IEnumerable<string> values)
		{
		}

		public void Add(string key, string value)
		{
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}

		public QueryString ToQueryString()
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http.Extensions\StreamCopyOperation.cs
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Extensions
{
	public static class StreamCopyOperation
	{
		public static Task CopyToAsync(Stream source, Stream destination, long? count, int bufferSize, CancellationToken cancel)
		{
			throw null;
		}

		public static Task CopyToAsync(Stream source, Stream destination, long? count, CancellationToken cancel)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http.Extensions\UriHelper.cs
using System;

namespace Microsoft.AspNetCore.Http.Extensions
{
	public static class UriHelper
	{
		public static string BuildAbsolute(string scheme, HostString host, PathString pathBase = default(PathString), PathString path = default(PathString), QueryString query = default(QueryString), FragmentString fragment = default(FragmentString))
		{
			throw null;
		}

		public static string BuildRelative(PathString pathBase = default(PathString), PathString path = default(PathString), QueryString query = default(QueryString), FragmentString fragment = default(FragmentString))
		{
			throw null;
		}

		public static string Encode(Uri uri)
		{
			throw null;
		}

		public static void FromAbsolute(string uri, out string scheme, out HostString host, out PathString path, out QueryString query, out FragmentString fragment)
		{
			throw null;
		}

		public static string GetDisplayUrl(this HttpRequest request)
		{
			throw null;
		}

		public static string GetEncodedPathAndQuery(this HttpRequest request)
		{
			throw null;
		}

		public static string GetEncodedUrl(this HttpRequest request)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http.Headers\RequestHeaders.cs
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Headers
{
	public class RequestHeaders
	{
		public IList<MediaTypeHeaderValue> Accept
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<StringWithQualityHeaderValue> AcceptCharset
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<StringWithQualityHeaderValue> AcceptEncoding
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<StringWithQualityHeaderValue> AcceptLanguage
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public CacheControlHeaderValue CacheControl
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public ContentDispositionHeaderValue ContentDisposition
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public long? ContentLength
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public ContentRangeHeaderValue ContentRange
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public MediaTypeHeaderValue ContentType
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<CookieHeaderValue> Cookie
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? Date
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? Expires
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IHeaderDictionary Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HostString Host
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<EntityTagHeaderValue> IfMatch
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? IfModifiedSince
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<EntityTagHeaderValue> IfNoneMatch
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public RangeConditionHeaderValue IfRange
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? IfUnmodifiedSince
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? LastModified
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public RangeHeaderValue Range
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public Uri Referer
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public RequestHeaders(IHeaderDictionary headers)
		{
		}

		public void Append(string name, object value)
		{
		}

		public void AppendList<T>(string name, IList<T> values)
		{
		}

		public IList<T> GetList<T>(string name)
		{
			throw null;
		}

		public T Get<T>(string name)
		{
			throw null;
		}

		public void Set(string name, object value)
		{
		}

		public void SetList<T>(string name, IList<T> values)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http.Headers\ResponseHeaders.cs
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Headers
{
	public class ResponseHeaders
	{
		public CacheControlHeaderValue CacheControl
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public ContentDispositionHeaderValue ContentDisposition
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public long? ContentLength
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public ContentRangeHeaderValue ContentRange
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public MediaTypeHeaderValue ContentType
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? Date
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public EntityTagHeaderValue ETag
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public DateTimeOffset? Expires
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IHeaderDictionary Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DateTimeOffset? LastModified
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public Uri Location
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<SetCookieHeaderValue> SetCookie
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public ResponseHeaders(IHeaderDictionary headers)
		{
		}

		public void Append(string name, object value)
		{
		}

		public void AppendList<T>(string name, IList<T> values)
		{
		}

		public IList<T> GetList<T>(string name)
		{
			throw null;
		}

		public T Get<T>(string name)
		{
			throw null;
		}

		public void Set(string name, object value)
		{
		}

		public void SetList<T>(string name, IList<T> values)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\CookieOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class CookieOptions
	{
		public string Domain
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public DateTimeOffset? Expires
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool HttpOnly
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool IsEssential
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan? MaxAge
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public SameSiteMode SameSite
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool Secure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public CookieOptions()
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IFormCollection.cs
using Microsoft.Extensions.Primitives;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public interface IFormCollection : IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		int Count
		{
			get;
		}

		IFormFileCollection Files
		{
			get;
		}

		StringValues this[string key]
		{
			get;
		}

		ICollection<string> Keys
		{
			get;
		}

		bool ContainsKey(string key);

		bool TryGetValue(string key, out StringValues value);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IFormFile.cs
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public interface IFormFile
	{
		string ContentDisposition
		{
			get;
		}

		string ContentType
		{
			get;
		}

		string FileName
		{
			get;
		}

		IHeaderDictionary Headers
		{
			get;
		}

		long Length
		{
			get;
		}

		string Name
		{
			get;
		}

		void CopyTo(Stream target);

		Task CopyToAsync(Stream target, CancellationToken cancellationToken = default(CancellationToken));

		Stream OpenReadStream();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IFormFileCollection.cs
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public interface IFormFileCollection : IEnumerable<IFormFile>, IEnumerable, IReadOnlyCollection<IFormFile>, IReadOnlyList<IFormFile>
	{
		IFormFile this[string name]
		{
			get;
		}

		IFormFile GetFile(string name);

		IReadOnlyList<IFormFile> GetFiles(string name);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IHeaderDictionary.cs
using Microsoft.Extensions.Primitives;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public interface IHeaderDictionary : ICollection<KeyValuePair<string, StringValues>>, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable, IDictionary<string, StringValues>
	{
		long? ContentLength
		{
			get;
			set;
		}

		new StringValues this[string key]
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IQueryCollection.cs
using Microsoft.Extensions.Primitives;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public interface IQueryCollection : IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		int Count
		{
			get;
		}

		StringValues this[string key]
		{
			get;
		}

		ICollection<string> Keys
		{
			get;
		}

		bool ContainsKey(string key);

		bool TryGetValue(string key, out StringValues value);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IRequestCookieCollection.cs
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public interface IRequestCookieCollection : IEnumerable<KeyValuePair<string, string>>, IEnumerable
	{
		int Count
		{
			get;
		}

		string this[string key]
		{
			get;
		}

		ICollection<string> Keys
		{
			get;
		}

		bool ContainsKey(string key);

		bool TryGetValue(string key, out string value);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IResponseCookies.cs
namespace Microsoft.AspNetCore.Http
{
	public interface IResponseCookies
	{
		void Append(string key, string value);

		void Append(string key, string value, CookieOptions options);

		void Delete(string key);

		void Delete(string key, CookieOptions options);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\ISession.cs
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public interface ISession
	{
		string Id
		{
			get;
		}

		bool IsAvailable
		{
			get;
		}

		IEnumerable<string> Keys
		{
			get;
		}

		void Clear();

		Task CommitAsync(CancellationToken cancellationToken = default(CancellationToken));

		Task LoadAsync(CancellationToken cancellationToken = default(CancellationToken));

		void Remove(string key);

		void Set(string key, byte[] value);

		bool TryGetValue(string key, out byte[] value);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\SameSiteMode.cs
namespace Microsoft.AspNetCore.Http
{
	public enum SameSiteMode
	{
		Unspecified = -1,
		None,
		Lax,
		Strict
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\WebSocketAcceptContext.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class WebSocketAcceptContext
	{
		public virtual string SubProtocol
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\FeatureCollection.cs
using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http.Features
{
	public class FeatureCollection : IFeatureCollection, IEnumerable<KeyValuePair<Type, object>>, IEnumerable
	{
		public bool IsReadOnly
		{
			get
			{
				throw null;
			}
		}

		public object this[Type key]
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public virtual int Revision
		{
			get
			{
				throw null;
			}
		}

		public FeatureCollection()
		{
		}

		public FeatureCollection(IFeatureCollection defaults)
		{
		}

		public IEnumerator<KeyValuePair<Type, object>> GetEnumerator()
		{
			throw null;
		}

		public TFeature Get<TFeature>()
		{
			throw null;
		}

		public void Set<TFeature>(TFeature instance)
		{
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\FeatureReference.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public struct FeatureReference<T>
	{
		private T _feature;

		private int _dummyPrimitive;

		public static readonly FeatureReference<T> Default;

		public T Fetch(IFeatureCollection features)
		{
			throw null;
		}

		public T Update(IFeatureCollection features, T feature)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\FeatureReferences.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public struct FeatureReferences<TCache>
	{
		private object _dummy;

		private int _dummyPrimitive;

		public TCache Cache;

		public IFeatureCollection Collection
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int Revision
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FeatureReferences(IFeatureCollection collection)
		{
			throw null;
		}

		public TFeature Fetch<TFeature>(ref TFeature cached, Func<IFeatureCollection, TFeature> factory) where TFeature : class
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public TFeature Fetch<TFeature, TState>(ref TFeature cached, TState state, Func<TState, TFeature> factory) where TFeature : class
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Initalize(IFeatureCollection collection)
		{
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Initalize(IFeatureCollection collection, int revision)
		{
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\HttpsCompressionMode.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public enum HttpsCompressionMode
	{
		Default,
		DoNotCompress,
		Compress
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IFeatureCollection.cs
using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IFeatureCollection : IEnumerable<KeyValuePair<Type, object>>, IEnumerable
	{
		bool IsReadOnly
		{
			get;
		}

		object this[Type key]
		{
			get;
			set;
		}

		int Revision
		{
			get;
		}

		TFeature Get<TFeature>();

		void Set<TFeature>(TFeature instance);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IFormFeature.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IFormFeature
	{
		IFormCollection Form
		{
			get;
			set;
		}

		bool HasFormContentType
		{
			get;
		}

		IFormCollection ReadForm();

		Task<IFormCollection> ReadFormAsync(CancellationToken cancellationToken);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpBodyControlFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpBodyControlFeature
	{
		bool AllowSynchronousIO
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpBufferingFeature.cs
using System;

namespace Microsoft.AspNetCore.Http.Features
{
	[Obsolete("See IHttpRequestBodyFeature or IHttpResponseBodyFeature DisableBuffering", true)]
	public interface IHttpBufferingFeature
	{
		void DisableRequestBuffering();

		void DisableResponseBuffering();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpConnectionFeature.cs
using System.Net;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpConnectionFeature
	{
		string ConnectionId
		{
			get;
			set;
		}

		IPAddress LocalIpAddress
		{
			get;
			set;
		}

		int LocalPort
		{
			get;
			set;
		}

		IPAddress RemoteIpAddress
		{
			get;
			set;
		}

		int RemotePort
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpMaxRequestBodySizeFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpMaxRequestBodySizeFeature
	{
		bool IsReadOnly
		{
			get;
		}

		long? MaxRequestBodySize
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpRequestFeature.cs
using System.IO;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpRequestFeature
	{
		Stream Body
		{
			get;
			set;
		}

		IHeaderDictionary Headers
		{
			get;
			set;
		}

		string Method
		{
			get;
			set;
		}

		string Path
		{
			get;
			set;
		}

		string PathBase
		{
			get;
			set;
		}

		string Protocol
		{
			get;
			set;
		}

		string QueryString
		{
			get;
			set;
		}

		string RawTarget
		{
			get;
			set;
		}

		string Scheme
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpRequestIdentifierFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpRequestIdentifierFeature
	{
		string TraceIdentifier
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpRequestLifetimeFeature.cs
using System.Threading;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpRequestLifetimeFeature
	{
		CancellationToken RequestAborted
		{
			get;
			set;
		}

		void Abort();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpRequestTrailersFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpRequestTrailersFeature
	{
		bool Available
		{
			get;
		}

		IHeaderDictionary Trailers
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpResetFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpResetFeature
	{
		void Reset(int errorCode);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpResponseBodyFeature.cs
using System.IO;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpResponseBodyFeature
	{
		Stream Stream
		{
			get;
		}

		PipeWriter Writer
		{
			get;
		}

		Task CompleteAsync();

		void DisableBuffering();

		Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken = default(CancellationToken));

		Task StartAsync(CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpResponseFeature.cs
using System;
using System.IO;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpResponseFeature
	{
		[Obsolete("Use IHttpResponseBodyFeature.Stream instead.", false)]
		Stream Body
		{
			get;
			set;
		}

		bool HasStarted
		{
			get;
		}

		IHeaderDictionary Headers
		{
			get;
			set;
		}

		string ReasonPhrase
		{
			get;
			set;
		}

		int StatusCode
		{
			get;
			set;
		}

		void OnCompleted(Func<object, Task> callback, object state);

		void OnStarting(Func<object, Task> callback, object state);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpResponseTrailersFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpResponseTrailersFeature
	{
		IHeaderDictionary Trailers
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpsCompressionFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpsCompressionFeature
	{
		HttpsCompressionMode Mode
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpSendFileFeature.cs
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	[Obsolete("Use IHttpResponseBodyFeature instead.", true)]
	public interface IHttpSendFileFeature
	{
		Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellation);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpUpgradeFeature.cs
using System.IO;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpUpgradeFeature
	{
		bool IsUpgradableRequest
		{
			get;
		}

		Task<Stream> UpgradeAsync();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpWebSocketFeature.cs
using System.Net.WebSockets;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpWebSocketFeature
	{
		bool IsWebSocketRequest
		{
			get;
		}

		Task<WebSocket> AcceptAsync(WebSocketAcceptContext context);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IItemsFeature.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IItemsFeature
	{
		IDictionary<object, object> Items
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IQueryFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IQueryFeature
	{
		IQueryCollection Query
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IRequestBodyPipeFeature.cs
using System.IO.Pipelines;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IRequestBodyPipeFeature
	{
		PipeReader Reader
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IRequestCookiesFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IRequestCookiesFeature
	{
		IRequestCookieCollection Cookies
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IResponseCookiesFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IResponseCookiesFeature
	{
		IResponseCookies Cookies
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IServerVariablesFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IServerVariablesFeature
	{
		string this[string variableName]
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IServiceProvidersFeature.cs
using System;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IServiceProvidersFeature
	{
		IServiceProvider RequestServices
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\ISessionFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface ISessionFeature
	{
		ISession Session
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\ITlsConnectionFeature.cs
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface ITlsConnectionFeature
	{
		X509Certificate2 ClientCertificate
		{
			get;
			set;
		}

		Task<X509Certificate2> GetClientCertificateAsync(CancellationToken cancellationToken);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\ITlsTokenBindingFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface ITlsTokenBindingFeature
	{
		byte[] GetProvidedTokenBindingId();

		byte[] GetReferredTokenBindingId();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\ITrackingConsentFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface ITrackingConsentFeature
	{
		bool CanTrack
		{
			get;
		}

		bool HasConsent
		{
			get;
		}

		bool IsConsentNeeded
		{
			get;
		}

		string CreateConsentCookie();

		void GrantConsent();

		void WithdrawConsent();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features.Authentication\IHttpAuthenticationFeature.cs
using System.Security.Claims;

namespace Microsoft.AspNetCore.Http.Features.Authentication
{
	public interface IHttpAuthenticationFeature
	{
		ClaimsPrincipal User
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.Builder\CertificateForwardingBuilderExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class CertificateForwardingBuilderExtensions
	{
		public static IApplicationBuilder UseCertificateForwarding(this IApplicationBuilder app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.Builder\ForwardedHeadersExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class ForwardedHeadersExtensions
	{
		public static IApplicationBuilder UseForwardedHeaders(this IApplicationBuilder builder)
		{
			throw null;
		}

		public static IApplicationBuilder UseForwardedHeaders(this IApplicationBuilder builder, ForwardedHeadersOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.Builder\ForwardedHeadersOptions.cs
using Microsoft.AspNetCore.HttpOverrides;
using System.Collections.Generic;
using System.Net;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class ForwardedHeadersOptions
	{
		public IList<string> AllowedHosts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardedForHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ForwardedHeaders ForwardedHeaders
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardedHostHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ForwardedProtoHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int? ForwardLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<IPNetwork> KnownNetworks
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<IPAddress> KnownProxies
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string OriginalForHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string OriginalHostHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string OriginalProtoHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool RequireHeaderSymmetry
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.Builder\HttpMethodOverrideExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class HttpMethodOverrideExtensions
	{
		public static IApplicationBuilder UseHttpMethodOverride(this IApplicationBuilder builder)
		{
			throw null;
		}

		public static IApplicationBuilder UseHttpMethodOverride(this IApplicationBuilder builder, HttpMethodOverrideOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.Builder\HttpMethodOverrideOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class HttpMethodOverrideOptions
	{
		public string FormFieldName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.HttpOverrides\CertificateForwardingMiddleware.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public class CertificateForwardingMiddleware
	{
		public CertificateForwardingMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IOptions<CertificateForwardingOptions> options)
		{
		}

		public Task Invoke(HttpContext httpContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.HttpOverrides\CertificateForwardingOptions.cs
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public class CertificateForwardingOptions
	{
		public Func<string, X509Certificate2> HeaderConverter;

		public string CertificateHeader
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.HttpOverrides\ForwardedHeaders.cs
using System;

namespace Microsoft.AspNetCore.HttpOverrides
{
	[Flags]
	public enum ForwardedHeaders
	{
		None = 0x0,
		XForwardedFor = 0x1,
		XForwardedHost = 0x2,
		XForwardedProto = 0x4,
		All = 0x7
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.HttpOverrides\ForwardedHeadersDefaults.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public static class ForwardedHeadersDefaults
	{
		public static string XForwardedForHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static string XForwardedHostHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static string XForwardedProtoHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static string XOriginalForHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static string XOriginalHostHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static string XOriginalProtoHeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.HttpOverrides\ForwardedHeadersMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public class ForwardedHeadersMiddleware
	{
		public ForwardedHeadersMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IOptions<ForwardedHeadersOptions> options)
		{
		}

		public void ApplyForwarders(HttpContext context)
		{
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.HttpOverrides\HttpMethodOverrideMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public class HttpMethodOverrideMiddleware
	{
		public HttpMethodOverrideMiddleware(RequestDelegate next, IOptions<HttpMethodOverrideOptions> options)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.AspNetCore.HttpOverrides\IPNetwork.cs
using System.Net;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public class IPNetwork
	{
		public IPAddress Prefix
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int PrefixLength
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IPNetwork(IPAddress prefix, int prefixLength)
		{
		}

		public bool Contains(IPAddress address)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpOverrides\Microsoft.Extensions.DependencyInjection\CertificateForwardingServiceExtensions.cs
using Microsoft.AspNetCore.HttpOverrides;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class CertificateForwardingServiceExtensions
	{
		public static IServiceCollection AddCertificateForwarding(this IServiceCollection services, Action<CertificateForwardingOptions> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.Builder\HstsBuilderExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class HstsBuilderExtensions
	{
		public static IApplicationBuilder UseHsts(this IApplicationBuilder app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.Builder\HstsServicesExtensions.cs
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class HstsServicesExtensions
	{
		public static IServiceCollection AddHsts(this IServiceCollection services, Action<HstsOptions> configureOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.Builder\HttpsPolicyBuilderExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class HttpsPolicyBuilderExtensions
	{
		public static IApplicationBuilder UseHttpsRedirection(this IApplicationBuilder app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.Builder\HttpsRedirectionServicesExtensions.cs
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class HttpsRedirectionServicesExtensions
	{
		public static IServiceCollection AddHttpsRedirection(this IServiceCollection services, Action<HttpsRedirectionOptions> configureOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.HttpsPolicy\HstsMiddleware.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HttpsPolicy
{
	public class HstsMiddleware
	{
		public HstsMiddleware(RequestDelegate next, IOptions<HstsOptions> options)
		{
		}

		public HstsMiddleware(RequestDelegate next, IOptions<HstsOptions> options, ILoggerFactory loggerFactory)
		{
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.HttpsPolicy\HstsOptions.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.HttpsPolicy
{
	public class HstsOptions
	{
		public IList<string> ExcludedHosts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IncludeSubDomains
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan MaxAge
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool Preload
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.HttpsPolicy\HttpsRedirectionMiddleware.cs
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HttpsPolicy
{
	public class HttpsRedirectionMiddleware
	{
		public HttpsRedirectionMiddleware(RequestDelegate next, IOptions<HttpsRedirectionOptions> options, IConfiguration config, ILoggerFactory loggerFactory)
		{
		}

		public HttpsRedirectionMiddleware(RequestDelegate next, IOptions<HttpsRedirectionOptions> options, IConfiguration config, ILoggerFactory loggerFactory, IServerAddressesFeature serverAddressesFeature)
		{
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.HttpsPolicy\Microsoft.AspNetCore.HttpsPolicy\HttpsRedirectionOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.HttpsPolicy
{
	public class HttpsRedirectionOptions
	{
		public int? HttpsPort
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int RedirectStatusCode
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\AspNetRoleManager.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;

namespace Microsoft.AspNetCore.Identity
{
	public class AspNetRoleManager<TRole> : RoleManager<TRole>, IDisposable where TRole : class
	{
		protected override CancellationToken CancellationToken
		{
			get
			{
				throw null;
			}
		}

		public AspNetRoleManager(IRoleStore<TRole> store, IEnumerable<IRoleValidator<TRole>> roleValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, ILogger<RoleManager<TRole>> logger, IHttpContextAccessor contextAccessor)
			: base((IRoleStore<TRole>)null, (IEnumerable<IRoleValidator<TRole>>)null, (ILookupNormalizer)null, (IdentityErrorDescriber)null, (ILogger<RoleManager<TRole>>)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\AspNetUserManager.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading;

namespace Microsoft.AspNetCore.Identity
{
	public class AspNetUserManager<TUser> : UserManager<TUser>, IDisposable where TUser : class
	{
		protected override CancellationToken CancellationToken
		{
			get
			{
				throw null;
			}
		}

		public AspNetUserManager(IUserStore<TUser> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<TUser> passwordHasher, IEnumerable<IUserValidator<TUser>> userValidators, IEnumerable<IPasswordValidator<TUser>> passwordValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<TUser>> logger)
			: base((IUserStore<TUser>)null, (IOptions<IdentityOptions>)null, (IPasswordHasher<TUser>)null, (IEnumerable<IUserValidator<TUser>>)null, (IEnumerable<IPasswordValidator<TUser>>)null, (ILookupNormalizer)null, (IdentityErrorDescriber)null, (IServiceProvider)null, (ILogger<UserManager<TUser>>)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\DataProtectionTokenProviderOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Identity
{
	public class DataProtectionTokenProviderOptions
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan TokenLifespan
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\DataProtectorTokenProvider.cs
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity
{
	public class DataProtectorTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser> where TUser : class
	{
		public ILogger<DataProtectorTokenProvider<TUser>> Logger
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Name
		{
			get
			{
				throw null;
			}
		}

		protected DataProtectionTokenProviderOptions Options
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected IDataProtector Protector
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DataProtectorTokenProvider(IDataProtectionProvider dataProtectionProvider, IOptions<DataProtectionTokenProviderOptions> options, ILogger<DataProtectorTokenProvider<TUser>> logger)
		{
		}

		public virtual Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public virtual Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public virtual Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\ExternalLoginInfo.cs
using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Identity
{
	public class ExternalLoginInfo : UserLoginInfo
	{
		public AuthenticationProperties AuthenticationProperties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IEnumerable<AuthenticationToken> AuthenticationTokens
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ClaimsPrincipal Principal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ExternalLoginInfo(ClaimsPrincipal principal, string loginProvider, string providerKey, string displayName)
			: base(null, null, null)
		{
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\IdentityBuilderExtensions.cs
namespace Microsoft.AspNetCore.Identity
{
	public static class IdentityBuilderExtensions
	{
		public static IdentityBuilder AddDefaultTokenProviders(this IdentityBuilder builder)
		{
			throw null;
		}

		public static IdentityBuilder AddSignInManager(this IdentityBuilder builder)
		{
			throw null;
		}

		public static IdentityBuilder AddSignInManager<TSignInManager>(this IdentityBuilder builder) where TSignInManager : class
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\IdentityConstants.cs
namespace Microsoft.AspNetCore.Identity
{
	public class IdentityConstants
	{
		public static readonly string ApplicationScheme;

		public static readonly string ExternalScheme;

		public static readonly string TwoFactorRememberMeScheme;

		public static readonly string TwoFactorUserIdScheme;
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\IdentityCookieAuthenticationBuilderExtensions.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.AspNetCore.Identity
{
	public static class IdentityCookieAuthenticationBuilderExtensions
	{
		public static OptionsBuilder<CookieAuthenticationOptions> AddApplicationCookie(this AuthenticationBuilder builder)
		{
			throw null;
		}

		public static OptionsBuilder<CookieAuthenticationOptions> AddExternalCookie(this AuthenticationBuilder builder)
		{
			throw null;
		}

		public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder)
		{
			throw null;
		}

		public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder, Action<IdentityCookiesBuilder> configureCookies)
		{
			throw null;
		}

		public static OptionsBuilder<CookieAuthenticationOptions> AddTwoFactorRememberMeCookie(this AuthenticationBuilder builder)
		{
			throw null;
		}

		public static OptionsBuilder<CookieAuthenticationOptions> AddTwoFactorUserIdCookie(this AuthenticationBuilder builder)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\IdentityCookiesBuilder.cs
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Identity
{
	public class IdentityCookiesBuilder
	{
		public OptionsBuilder<CookieAuthenticationOptions> ApplicationCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public OptionsBuilder<CookieAuthenticationOptions> ExternalCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public OptionsBuilder<CookieAuthenticationOptions> TwoFactorRememberMeCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public OptionsBuilder<CookieAuthenticationOptions> TwoFactorUserIdCookie
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\ISecurityStampValidator.cs
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity
{
	public interface ISecurityStampValidator
	{
		Task ValidateAsync(CookieValidatePrincipalContext context);
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\ITwoFactorSecurityStampValidator.cs
namespace Microsoft.AspNetCore.Identity
{
	public interface ITwoFactorSecurityStampValidator : ISecurityStampValidator
	{
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\SecurityStampRefreshingPrincipalContext.cs
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Identity
{
	public class SecurityStampRefreshingPrincipalContext
	{
		public ClaimsPrincipal CurrentPrincipal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public ClaimsPrincipal NewPrincipal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\SecurityStampValidator.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity
{
	public static class SecurityStampValidator
	{
		public static Task ValidateAsync<TValidator>(CookieValidatePrincipalContext context) where TValidator : ISecurityStampValidator
		{
			throw null;
		}

		public static Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
		{
			throw null;
		}
	}
	public class SecurityStampValidator<TUser> : ISecurityStampValidator where TUser : class
	{
		public ISystemClock Clock
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ILogger Logger
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public SecurityStampValidatorOptions Options
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public SignInManager<TUser> SignInManager
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public SecurityStampValidator(IOptions<SecurityStampValidatorOptions> options, SignInManager<TUser> signInManager, ISystemClock clock, ILoggerFactory logger)
		{
		}

		[DebuggerStepThrough]
		protected virtual Task SecurityStampVerified(TUser user, CookieValidatePrincipalContext context)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public virtual Task ValidateAsync(CookieValidatePrincipalContext context)
		{
			throw null;
		}

		protected virtual Task<TUser> VerifySecurityStamp(ClaimsPrincipal principal)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\SecurityStampValidatorOptions.cs
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity
{
	public class SecurityStampValidatorOptions
	{
		public Func<SecurityStampRefreshingPrincipalContext, Task> OnRefreshingPrincipal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan ValidationInterval
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.AspNetCore.Identity\TwoFactorSecurityStampValidator.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity
{
	public class TwoFactorSecurityStampValidator<TUser> : SecurityStampValidator<TUser>, ISecurityStampValidator, ITwoFactorSecurityStampValidator where TUser : class
	{
		public TwoFactorSecurityStampValidator(IOptions<SecurityStampValidatorOptions> options, SignInManager<TUser> signInManager, ISystemClock clock, ILoggerFactory logger)
			: base((IOptions<SecurityStampValidatorOptions>)null, (SignInManager<TUser>)null, (ISystemClock)null, (ILoggerFactory)null)
		{
		}

		protected override Task SecurityStampVerified(TUser user, CookieValidatePrincipalContext context)
		{
			throw null;
		}

		protected override Task<TUser> VerifySecurityStamp(ClaimsPrincipal principal)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Identity\Microsoft.Extensions.DependencyInjection\IdentityServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class IdentityServiceCollectionExtensions
	{
		public static IdentityBuilder AddIdentity<TUser, TRole>(this IServiceCollection services) where TUser : class where TRole : class
		{
			throw null;
		}

		public static IdentityBuilder AddIdentity<TUser, TRole>(this IServiceCollection services, Action<IdentityOptions> setupAction) where TUser : class where TRole : class
		{
			throw null;
		}

		public static IServiceCollection ConfigureApplicationCookie(this IServiceCollection services, Action<CookieAuthenticationOptions> configure)
		{
			throw null;
		}

		public static IServiceCollection ConfigureExternalCookie(this IServiceCollection services, Action<CookieAuthenticationOptions> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Builder\ApplicationBuilderExtensions.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class ApplicationBuilderExtensions
	{
		public static IApplicationBuilder UseRequestLocalization(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseRequestLocalization(this IApplicationBuilder app, RequestLocalizationOptions options)
		{
			throw null;
		}

		public static IApplicationBuilder UseRequestLocalization(this IApplicationBuilder app, Action<RequestLocalizationOptions> optionsAction)
		{
			throw null;
		}

		public static IApplicationBuilder UseRequestLocalization(this IApplicationBuilder app, params string[] cultures)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Builder\RequestLocalizationOptions.cs
using Microsoft.AspNetCore.Localization;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class RequestLocalizationOptions
	{
		public RequestCulture DefaultRequestCulture
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public bool FallBackToParentCultures
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool FallBackToParentUICultures
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<IRequestCultureProvider> RequestCultureProviders
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<CultureInfo> SupportedCultures
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<CultureInfo> SupportedUICultures
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RequestLocalizationOptions()
		{
		}

		public RequestLocalizationOptions AddSupportedCultures(params string[] cultures)
		{
			throw null;
		}

		public RequestLocalizationOptions AddSupportedUICultures(params string[] uiCultures)
		{
			throw null;
		}

		public RequestLocalizationOptions SetDefaultCulture(string defaultCulture)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Builder\RequestLocalizationOptionsExtensions.cs
using Microsoft.AspNetCore.Localization;

namespace Microsoft.AspNetCore.Builder
{
	public static class RequestLocalizationOptionsExtensions
	{
		public static RequestLocalizationOptions AddInitialRequestCultureProvider(this RequestLocalizationOptions requestLocalizationOptions, RequestCultureProvider requestCultureProvider)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\AcceptLanguageHeaderRequestCultureProvider.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public class AcceptLanguageHeaderRequestCultureProvider : RequestCultureProvider
	{
		public int MaximumAcceptLanguageHeaderValuesToTry
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\CookieRequestCultureProvider.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public class CookieRequestCultureProvider : RequestCultureProvider
	{
		public static readonly string DefaultCookieName;

		public string CookieName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}

		public static string MakeCookieValue(RequestCulture requestCulture)
		{
			throw null;
		}

		public static ProviderCultureResult ParseCookieValue(string value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\CustomRequestCultureProvider.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public class CustomRequestCultureProvider : RequestCultureProvider
	{
		public CustomRequestCultureProvider(Func<HttpContext, Task<ProviderCultureResult>> provider)
		{
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\IRequestCultureFeature.cs
namespace Microsoft.AspNetCore.Localization
{
	public interface IRequestCultureFeature
	{
		IRequestCultureProvider Provider
		{
			get;
		}

		RequestCulture RequestCulture
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\IRequestCultureProvider.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public interface IRequestCultureProvider
	{
		Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext);
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\ProviderCultureResult.cs
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Localization
{
	public class ProviderCultureResult
	{
		public IList<StringSegment> Cultures
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<StringSegment> UICultures
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ProviderCultureResult(StringSegment culture)
		{
		}

		public ProviderCultureResult(StringSegment culture, StringSegment uiCulture)
		{
		}

		public ProviderCultureResult(IList<StringSegment> cultures)
		{
		}

		public ProviderCultureResult(IList<StringSegment> cultures, IList<StringSegment> uiCultures)
		{
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\QueryStringRequestCultureProvider.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public class QueryStringRequestCultureProvider : RequestCultureProvider
	{
		public string QueryStringKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string UIQueryStringKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\RequestCulture.cs
using System.Globalization;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Localization
{
	public class RequestCulture
	{
		public CultureInfo Culture
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CultureInfo UICulture
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RequestCulture(CultureInfo culture)
		{
		}

		public RequestCulture(CultureInfo culture, CultureInfo uiCulture)
		{
		}

		public RequestCulture(string culture)
		{
		}

		public RequestCulture(string culture, string uiCulture)
		{
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\RequestCultureFeature.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Localization
{
	public class RequestCultureFeature : IRequestCultureFeature
	{
		public IRequestCultureProvider Provider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RequestCulture RequestCulture
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RequestCultureFeature(RequestCulture requestCulture, IRequestCultureProvider provider)
		{
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\RequestCultureProvider.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public abstract class RequestCultureProvider : IRequestCultureProvider
	{
		protected static readonly Task<ProviderCultureResult> NullProviderCultureResult;

		public RequestLocalizationOptions Options
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public abstract Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext);
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\RequestLocalizationMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public class RequestLocalizationMiddleware
	{
		[Obsolete("This constructor is obsolete and will be removed in a future version. Use RequestLocalizationMiddleware(RequestDelegate next, IOptions<RequestLocalizationOptions> options, ILoggerFactory loggerFactory) instead")]
		public RequestLocalizationMiddleware(RequestDelegate next, IOptions<RequestLocalizationOptions> options)
		{
		}

		[ActivatorUtilitiesConstructor]
		public RequestLocalizationMiddleware(RequestDelegate next, IOptions<RequestLocalizationOptions> options, ILoggerFactory loggerFactory)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization.Routing\Microsoft.AspNetCore.Localization.Routing\RouteDataRequestCultureProvider.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization.Routing
{
	public class RouteDataRequestCultureProvider : RequestCultureProvider
	{
		public string RouteDataStringKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string UIRouteDataStringKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Metadata\Microsoft.AspNetCore.Authorization\IAllowAnonymous.cs
namespace Microsoft.AspNetCore.Authorization
{
	public interface IAllowAnonymous
	{
	}
}


// Microsoft.AspNetCore.Metadata\Microsoft.AspNetCore.Authorization\IAuthorizeData.cs
namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizeData
	{
		string AuthenticationSchemes
		{
			get;
			set;
		}

		string Policy
		{
			get;
			set;
		}

		string Roles
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Builder\EndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Builder
{
	public static class EndpointRouteBuilderExtensions
	{
		public static IEndpointConventionBuilder Map(this IEndpointRouteBuilder endpoints, RoutePattern pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder Map(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapDelete(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapGet(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapMethods(this IEndpointRouteBuilder endpoints, string pattern, IEnumerable<string> httpMethods, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapPost(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapPut(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Builder\EndpointRoutingApplicationBuilderExtensions.cs
using Microsoft.AspNetCore.Routing;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class EndpointRoutingApplicationBuilderExtensions
	{
		public static IApplicationBuilder UseEndpoints(this IApplicationBuilder builder, Action<IEndpointRouteBuilder> configure)
		{
			throw null;
		}

		public static IApplicationBuilder UseRouting(this IApplicationBuilder builder)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Builder\FallbackEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder
{
	public static class FallbackEndpointRouteBuilderExtensions
	{
		public static readonly string DefaultPattern;

		public static IEndpointConventionBuilder MapFallback(this IEndpointRouteBuilder endpoints, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapFallback(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Builder\MapRouteRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder
{
	public static class MapRouteRouteBuilderExtensions
	{
		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string name, string template)
		{
			throw null;
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string name, string template, object defaults)
		{
			throw null;
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string name, string template, object defaults, object constraints)
		{
			throw null;
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string name, string template, object defaults, object constraints, object dataTokens)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Builder\RouterMiddleware.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder
{
	public class RouterMiddleware
	{
		public RouterMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IRouter router)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext httpContext)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Builder\RoutingBuilderExtensions.cs
using Microsoft.AspNetCore.Routing;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class RoutingBuilderExtensions
	{
		public static IApplicationBuilder UseRouter(this IApplicationBuilder builder, IRouter router)
		{
			throw null;
		}

		public static IApplicationBuilder UseRouter(this IApplicationBuilder builder, Action<IRouteBuilder> action)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Builder\RoutingEndpointConventionBuilderExtensions.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class RoutingEndpointConventionBuilderExtensions
	{
		public static TBuilder RequireHost<TBuilder>(this TBuilder builder, params string[] hosts) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder WithDisplayName<TBuilder>(this TBuilder builder, Func<EndpointBuilder, string> func) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder WithDisplayName<TBuilder>(this TBuilder builder, string displayName) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder WithMetadata<TBuilder>(this TBuilder builder, params object[] items) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\CompositeEndpointDataSource.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.AspNetCore.Routing
{
	[DebuggerDisplay("{DebuggerDisplayString,nq}")]
	public sealed class CompositeEndpointDataSource : EndpointDataSource
	{
		public IEnumerable<EndpointDataSource> DataSources
		{
			get
			{
				throw null;
			}
		}

		public override IReadOnlyList<Endpoint> Endpoints
		{
			get
			{
				throw null;
			}
		}

		public CompositeEndpointDataSource(IEnumerable<EndpointDataSource> endpointDataSources)
		{
		}

		public override IChangeToken GetChangeToken()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\DataTokensMetadata.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public sealed class DataTokensMetadata : IDataTokensMetadata
	{
		public IReadOnlyDictionary<string, object> DataTokens
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DataTokensMetadata(IReadOnlyDictionary<string, object> dataTokens)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\DefaultEndpointDataSource.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public sealed class DefaultEndpointDataSource : EndpointDataSource
	{
		public override IReadOnlyList<Endpoint> Endpoints
		{
			get
			{
				throw null;
			}
		}

		public DefaultEndpointDataSource(params Endpoint[] endpoints)
		{
		}

		public DefaultEndpointDataSource(IEnumerable<Endpoint> endpoints)
		{
		}

		public override IChangeToken GetChangeToken()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\DefaultInlineConstraintResolver.cs
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.AspNetCore.Routing
{
	public class DefaultInlineConstraintResolver : IInlineConstraintResolver
	{
		public DefaultInlineConstraintResolver(IOptions<RouteOptions> routeOptions, IServiceProvider serviceProvider)
		{
		}

		public virtual IRouteConstraint ResolveConstraint(string inlineConstraint)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\EndpointDataSource.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public abstract class EndpointDataSource
	{
		public abstract IReadOnlyList<Endpoint> Endpoints
		{
			get;
		}

		public abstract IChangeToken GetChangeToken();
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\EndpointNameMetadata.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class EndpointNameMetadata : IEndpointNameMetadata
	{
		public string EndpointName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public EndpointNameMetadata(string endpointName)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\HostAttribute.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	public sealed class HostAttribute : Attribute, IHostMetadata
	{
		public IReadOnlyList<string> Hosts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HostAttribute(string host)
		{
		}

		public HostAttribute(params string[] hosts)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\HttpMethodMetadata.cs
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	public sealed class HttpMethodMetadata : IHttpMethodMetadata
	{
		public bool AcceptCorsPreflight
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<string> HttpMethods
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HttpMethodMetadata(IEnumerable<string> httpMethods)
		{
		}

		public HttpMethodMetadata(IEnumerable<string> httpMethods, bool acceptCorsPreflight)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IDataTokensMetadata.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public interface IDataTokensMetadata
	{
		IReadOnlyDictionary<string, object> DataTokens
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IDynamicEndpointMetadata.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IDynamicEndpointMetadata
	{
		bool IsDynamic
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IEndpointAddressScheme.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public interface IEndpointAddressScheme<TAddress>
	{
		IEnumerable<Endpoint> FindEndpoints(TAddress address);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IEndpointNameMetadata.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IEndpointNameMetadata
	{
		string EndpointName
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IEndpointRouteBuilder.cs
using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public interface IEndpointRouteBuilder
	{
		ICollection<EndpointDataSource> DataSources
		{
			get;
		}

		IServiceProvider ServiceProvider
		{
			get;
		}

		IApplicationBuilder CreateApplicationBuilder();
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IHostMetadata.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public interface IHostMetadata
	{
		IReadOnlyList<string> Hosts
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IHttpMethodMetadata.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public interface IHttpMethodMetadata
	{
		bool AcceptCorsPreflight
		{
			get;
		}

		IReadOnlyList<string> HttpMethods
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IInlineConstraintResolver.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IInlineConstraintResolver
	{
		IRouteConstraint ResolveConstraint(string inlineConstraint);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\INamedRouter.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface INamedRouter : IRouter
	{
		string Name
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\InlineRouteParameterParser.cs
using Microsoft.AspNetCore.Routing.Template;

namespace Microsoft.AspNetCore.Routing
{
	public static class InlineRouteParameterParser
	{
		public static TemplatePart ParseRouteParameter(string routeParameter)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IRouteBuilder.cs
using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public interface IRouteBuilder
	{
		IApplicationBuilder ApplicationBuilder
		{
			get;
		}

		IRouter DefaultHandler
		{
			get;
			set;
		}

		IList<IRouter> Routes
		{
			get;
		}

		IServiceProvider ServiceProvider
		{
			get;
		}

		IRouter Build();
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IRouteCollection.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IRouteCollection : IRouter
	{
		void Add(IRouter router);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\IRouteNameMetadata.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IRouteNameMetadata
	{
		string RouteName
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\ISuppressLinkGenerationMetadata.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface ISuppressLinkGenerationMetadata
	{
		bool SuppressLinkGeneration
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\ISuppressMatchingMetadata.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface ISuppressMatchingMetadata
	{
		bool SuppressMatching
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\LinkGeneratorEndpointNameAddressExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public static class LinkGeneratorEndpointNameAddressExtensions
	{
		public static string GetPathByName(this LinkGenerator generator, HttpContext httpContext, string endpointName, object values, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}

		public static string GetPathByName(this LinkGenerator generator, string endpointName, object values, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}

		public static string GetUriByName(this LinkGenerator generator, HttpContext httpContext, string endpointName, object values, string scheme = null, HostString? host = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}

		public static string GetUriByName(this LinkGenerator generator, string endpointName, object values, string scheme, HostString host, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\LinkGeneratorRouteValuesAddressExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public static class LinkGeneratorRouteValuesAddressExtensions
	{
		public static string GetPathByRouteValues(this LinkGenerator generator, HttpContext httpContext, string routeName, object values, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}

		public static string GetPathByRouteValues(this LinkGenerator generator, string routeName, object values, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}

		public static string GetUriByRouteValues(this LinkGenerator generator, HttpContext httpContext, string routeName, object values, string scheme = null, HostString? host = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}

		public static string GetUriByRouteValues(this LinkGenerator generator, string routeName, object values, string scheme, HostString host, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions options = null)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\LinkParser.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public abstract class LinkParser
	{
		public abstract RouteValueDictionary ParsePathByAddress<TAddress>(TAddress address, PathString path);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\LinkParserEndpointNameAddressExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public static class LinkParserEndpointNameAddressExtensions
	{
		public static RouteValueDictionary ParsePathByEndpointName(this LinkParser parser, string endpointName, PathString path)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\MatcherPolicy.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public abstract class MatcherPolicy
	{
		public abstract int Order
		{
			get;
		}

		protected static bool ContainsDynamicEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\ParameterPolicyFactory.cs
using Microsoft.AspNetCore.Routing.Patterns;

namespace Microsoft.AspNetCore.Routing
{
	public abstract class ParameterPolicyFactory
	{
		public abstract IParameterPolicy Create(RoutePatternParameterPart parameter, IParameterPolicy parameterPolicy);

		public IParameterPolicy Create(RoutePatternParameterPart parameter, RoutePatternParameterPolicyReference reference)
		{
			throw null;
		}

		public abstract IParameterPolicy Create(RoutePatternParameterPart parameter, string inlineText);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\PathTokenizer.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	internal struct PathTokenizer : IEnumerable<StringSegment>, IEnumerable, IReadOnlyCollection<StringSegment>, IReadOnlyList<StringSegment>
	{
		public struct Enumerator : IEnumerator<StringSegment>, IEnumerator, IDisposable
		{
			private readonly string _path;

			private int _index;

			private int _length;

			public StringSegment Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				get
				{
					throw null;
				}
			}

			public Enumerator(PathTokenizer tokenizer)
			{
				throw null;
			}

			public void Dispose()
			{
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Reset()
			{
			}
		}

		private readonly string _path;

		private int _count;

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public StringSegment this[int index]
		{
			get
			{
				throw null;
			}
		}

		public PathTokenizer(PathString path)
		{
			throw null;
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		IEnumerator<StringSegment> IEnumerable<StringSegment>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RequestDelegateRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public static class RequestDelegateRouteBuilderExtensions
	{
		public static IRouteBuilder MapDelete(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapDelete(this IRouteBuilder builder, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}

		public static IRouteBuilder MapGet(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapGet(this IRouteBuilder builder, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewareDelete(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewareGet(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewarePost(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewarePut(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewareRoute(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewareVerb(this IRouteBuilder builder, string verb, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapPost(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapPost(this IRouteBuilder builder, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}

		public static IRouteBuilder MapPut(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapPut(this IRouteBuilder builder, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapVerb(this IRouteBuilder builder, string verb, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapVerb(this IRouteBuilder builder, string verb, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\Route.cs
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public class Route : RouteBase
	{
		public string RouteTemplate
		{
			get
			{
				throw null;
			}
		}

		public Route(IRouter target, string routeTemplate, IInlineConstraintResolver inlineConstraintResolver)
			: base(null, null, null, null, null, null)
		{
		}

		public Route(IRouter target, string routeTemplate, RouteValueDictionary defaults, IDictionary<string, object> constraints, RouteValueDictionary dataTokens, IInlineConstraintResolver inlineConstraintResolver)
			: base(null, null, null, null, null, null)
		{
		}

		public Route(IRouter target, string routeName, string routeTemplate, RouteValueDictionary defaults, IDictionary<string, object> constraints, RouteValueDictionary dataTokens, IInlineConstraintResolver inlineConstraintResolver)
			: base(null, null, null, null, null, null)
		{
		}

		protected override Task OnRouteMatched(RouteContext context)
		{
			throw null;
		}

		protected override VirtualPathData OnVirtualPathGenerated(VirtualPathContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteBase.cs
using Microsoft.AspNetCore.Routing.Template;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public abstract class RouteBase : INamedRouter, IRouter
	{
		protected virtual IInlineConstraintResolver ConstraintResolver
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual IDictionary<string, IRouteConstraint> Constraints
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public virtual RouteValueDictionary DataTokens
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public virtual RouteValueDictionary Defaults
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public virtual string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public virtual RouteTemplate ParsedTemplate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
			}
		}

		public RouteBase(string template, string name, IInlineConstraintResolver constraintResolver, RouteValueDictionary defaults, IDictionary<string, object> constraints, RouteValueDictionary dataTokens)
		{
		}

		protected static IDictionary<string, IRouteConstraint> GetConstraints(IInlineConstraintResolver inlineConstraintResolver, RouteTemplate parsedTemplate, IDictionary<string, object> constraints)
		{
			throw null;
		}

		protected static RouteValueDictionary GetDefaults(RouteTemplate parsedTemplate, RouteValueDictionary defaults)
		{
			throw null;
		}

		public virtual VirtualPathData GetVirtualPath(VirtualPathContext context)
		{
			throw null;
		}

		protected abstract Task OnRouteMatched(RouteContext context);

		protected abstract VirtualPathData OnVirtualPathGenerated(VirtualPathContext context);

		public virtual Task RouteAsync(RouteContext context)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteBuilder.cs
using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteBuilder : IRouteBuilder
	{
		public IApplicationBuilder ApplicationBuilder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IRouter DefaultHandler
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<IRouter> Routes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IServiceProvider ServiceProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteBuilder(IApplicationBuilder applicationBuilder)
		{
		}

		public RouteBuilder(IApplicationBuilder applicationBuilder, IRouter defaultHandler)
		{
		}

		public IRouter Build()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteCollection.cs
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteCollection : IRouteCollection, IRouter
	{
		public int Count
		{
			get
			{
				throw null;
			}
		}

		public IRouter this[int index]
		{
			get
			{
				throw null;
			}
		}

		public void Add(IRouter router)
		{
		}

		public virtual VirtualPathData GetVirtualPath(VirtualPathContext context)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public virtual Task RouteAsync(RouteContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteConstraintBuilder.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteConstraintBuilder
	{
		public RouteConstraintBuilder(IInlineConstraintResolver inlineConstraintResolver, string displayName)
		{
		}

		public void AddConstraint(string key, object value)
		{
		}

		public void AddResolvedConstraint(string key, string constraintText)
		{
		}

		public IDictionary<string, IRouteConstraint> Build()
		{
			throw null;
		}

		public void SetOptional(string key)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteConstraintMatcher.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public static class RouteConstraintMatcher
	{
		public static bool Match(IDictionary<string, IRouteConstraint> constraints, RouteValueDictionary routeValues, HttpContext httpContext, IRouter route, RouteDirection routeDirection, ILogger logger)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteCreationException.cs
using System;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteCreationException : Exception
	{
		public RouteCreationException(string message)
		{
		}

		public RouteCreationException(string message, Exception innerException)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteEndpoint.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing.Patterns;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public sealed class RouteEndpoint : Endpoint
	{
		public int Order
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RoutePattern RoutePattern
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteEndpoint(RequestDelegate requestDelegate, RoutePattern routePattern, int order, EndpointMetadataCollection metadata, string displayName)
			: base(null, null, null)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteEndpointBuilder.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing.Patterns;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public sealed class RouteEndpointBuilder : EndpointBuilder
	{
		public int Order
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RoutePattern RoutePattern
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteEndpointBuilder(RequestDelegate requestDelegate, RoutePattern routePattern, int order)
		{
		}

		public override Endpoint Build()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteHandler.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteHandler : IRouteHandler, IRouter
	{
		public RouteHandler(RequestDelegate requestDelegate)
		{
		}

		public RequestDelegate GetRequestHandler(HttpContext httpContext, RouteData routeData)
		{
			throw null;
		}

		public VirtualPathData GetVirtualPath(VirtualPathContext context)
		{
			throw null;
		}

		public Task RouteAsync(RouteContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteNameMetadata.cs
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	public sealed class RouteNameMetadata : IRouteNameMetadata
	{
		public string RouteName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteNameMetadata(string routeName)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteOptions.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteOptions
	{
		public bool AppendTrailingSlash
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IDictionary<string, Type> ConstraintMap
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public bool LowercaseQueryStrings
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool LowercaseUrls
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool SuppressCheckForUnhandledSecurityMetadata
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		internal ICollection<EndpointDataSource> EndpointDataSources
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteValueEqualityComparer.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteValueEqualityComparer : IEqualityComparer<object>
	{
		public static readonly RouteValueEqualityComparer Default;

		public new bool Equals(object x, object y)
		{
			throw null;
		}

		public int GetHashCode(object obj)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteValuesAddress.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteValuesAddress
	{
		public RouteValueDictionary AmbientValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteValueDictionary ExplicitValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string RouteName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RoutingFeature.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class RoutingFeature : IRoutingFeature
	{
		public RouteData RouteData
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\SuppressLinkGenerationMetadata.cs
namespace Microsoft.AspNetCore.Routing
{
	public sealed class SuppressLinkGenerationMetadata : ISuppressLinkGenerationMetadata
	{
		public bool SuppressLinkGeneration
		{
			get
			{
				throw null;
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\SuppressMatchingMetadata.cs
namespace Microsoft.AspNetCore.Routing
{
	public sealed class SuppressMatchingMetadata : ISuppressMatchingMetadata
	{
		public bool SuppressMatching
		{
			get
			{
				throw null;
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\AlphaRouteConstraint.cs
using System.Text.RegularExpressions;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class AlphaRouteConstraint : RegexRouteConstraint
	{
		public AlphaRouteConstraint()
			: base((Regex)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\BoolRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class BoolRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\CompositeRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class CompositeRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public IEnumerable<IRouteConstraint> Constraints
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CompositeRouteConstraint(IEnumerable<IRouteConstraint> constraints)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\DateTimeRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class DateTimeRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\DecimalRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class DecimalRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\DoubleRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class DoubleRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\FileNameRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class FileNameRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\FloatRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class FloatRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\GuidRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class GuidRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\HttpMethodRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class HttpMethodRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public IList<string> AllowedMethods
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HttpMethodRouteConstraint(params string[] allowedMethods)
		{
		}

		public virtual bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\IntRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class IntRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\LengthRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class LengthRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public int MaxLength
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int MinLength
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LengthRouteConstraint(int length)
		{
		}

		public LengthRouteConstraint(int minLength, int maxLength)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\LongRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class LongRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\MaxLengthRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class MaxLengthRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public int MaxLength
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MaxLengthRouteConstraint(int maxLength)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\MaxRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class MaxRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public long Max
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MaxRouteConstraint(long max)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\MinLengthRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class MinLengthRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public int MinLength
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MinLengthRouteConstraint(int minLength)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\MinRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class MinRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public long Min
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MinRouteConstraint(long min)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\NonFileNameRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class NonFileNameRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\OptionalRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class OptionalRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public IRouteConstraint InnerConstraint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public OptionalRouteConstraint(IRouteConstraint innerConstraint)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\RangeRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class RangeRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public long Max
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public long Min
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RangeRouteConstraint(long min, long max)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\RegexInlineRouteConstraint.cs
using System.Text.RegularExpressions;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class RegexInlineRouteConstraint : RegexRouteConstraint
	{
		public RegexInlineRouteConstraint(string regexPattern)
			: base((Regex)null)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\RegexRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class RegexRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public Regex Constraint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RegexRouteConstraint(string regexPattern)
		{
		}

		public RegexRouteConstraint(Regex regex)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\RequiredRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class RequiredRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\StringRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class StringRouteConstraint : IParameterPolicy, IRouteConstraint
	{
		public StringRouteConstraint(string value)
		{
		}

		public bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.DecisionTree\DecisionCriterionValue.cs
namespace Microsoft.AspNetCore.Routing.DecisionTree
{
	internal readonly struct DecisionCriterionValue
	{
		private readonly object _value;

		public object Value
		{
			get
			{
				throw null;
			}
		}

		public DecisionCriterionValue(object value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.DecisionTree\IClassifier.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing.DecisionTree
{
	internal interface IClassifier<TItem>
	{
		IEqualityComparer<object> ValueComparer
		{
			get;
		}

		IDictionary<string, DecisionCriterionValue> GetCriteria(TItem item);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Internal\DfaGraphWriter.cs
using System;
using System.IO;

namespace Microsoft.AspNetCore.Routing.Internal
{
	public class DfaGraphWriter
	{
		public DfaGraphWriter(IServiceProvider services)
		{
		}

		public void Write(EndpointDataSource dataSource, TextWriter writer)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\Candidate.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing.Patterns;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing.Matching
{
	internal readonly struct Candidate
	{
		[Flags]
		public enum CandidateFlags
		{
			None = 0x0,
			HasDefaults = 0x1,
			HasCaptures = 0x2,
			HasCatchAll = 0x4,
			HasSlots = 0x7,
			HasComplexSegments = 0x8,
			HasConstraints = 0x10
		}

		public readonly Endpoint Endpoint;

		public readonly CandidateFlags Flags;

		public readonly KeyValuePair<string, object>[] Slots;

		public readonly (string parameterName, int segmentIndex, int slotIndex)[] Captures;

		public readonly (string parameterName, int segmentIndex, int slotIndex) CatchAll;

		public readonly (RoutePatternPathSegment pathSegment, int segmentIndex)[] ComplexSegments;

		public readonly KeyValuePair<string, IRouteConstraint>[] Constraints;

		public readonly int Score;

		public Candidate(Endpoint endpoint)
		{
			throw null;
		}

		public Candidate(Endpoint endpoint, int score, KeyValuePair<string, object>[] slots, (string, int, int)[] captures, in (string parameterName, int segmentIndex, int slotIndex) catchAll, (RoutePatternPathSegment, int)[] complexSegments, KeyValuePair<string, IRouteConstraint>[] constraints)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\CandidateSet.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public sealed class CandidateSet
	{
		internal CandidateState[] Candidates;

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public ref CandidateState this[int index]
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				throw null;
			}
		}

		public CandidateSet(Endpoint[] endpoints, RouteValueDictionary[] values, int[] scores)
		{
		}

		public void ExpandEndpoint(int index, IReadOnlyList<Endpoint> endpoints, IComparer<Endpoint> comparer)
		{
		}

		public bool IsValidCandidate(int index)
		{
			throw null;
		}

		public void ReplaceEndpoint(int index, Endpoint endpoint, RouteValueDictionary values)
		{
		}

		public void SetValidity(int index, bool value)
		{
		}

		internal CandidateSet(CandidateState[] candidates)
		{
		}

		internal CandidateSet(Candidate[] candidates)
		{
		}

		internal static bool IsValidCandidate(ref CandidateState candidate)
		{
			throw null;
		}

		internal static void SetValidity(ref CandidateState candidate, bool value)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\CandidateState.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public struct CandidateState
	{
		private object _dummy;

		private int _dummyPrimitive;

		public Endpoint Endpoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int Score
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteValueDictionary Values
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			internal set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\DfaState.cs
using System.Diagnostics;

namespace Microsoft.AspNetCore.Routing.Matching
{
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	internal readonly struct DfaState
	{
		public readonly Candidate[] Candidates;

		public readonly IEndpointSelectorPolicy[] Policies;

		public readonly JumpTable PathTransitions;

		public readonly PolicyJumpTable PolicyTransitions;

		public DfaState(Candidate[] candidates, IEndpointSelectorPolicy[] policies, JumpTable pathTransitions, PolicyJumpTable policyTransitions)
		{
			throw null;
		}

		public string DebuggerToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\EndpointMetadataComparer.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public sealed class EndpointMetadataComparer : IComparer<Endpoint>
	{
		internal EndpointMetadataComparer()
		{
		}

		int IComparer<Endpoint>.Compare(Endpoint x, Endpoint y)
		{
			throw null;
		}

		internal EndpointMetadataComparer(IServiceProvider services)
		{
		}
	}
	public abstract class EndpointMetadataComparer<TMetadata> : IComparer<Endpoint> where TMetadata : class
	{
		public static readonly EndpointMetadataComparer<TMetadata> Default;

		public int Compare(Endpoint x, Endpoint y)
		{
			throw null;
		}

		protected virtual int CompareMetadata(TMetadata x, TMetadata y)
		{
			throw null;
		}

		protected virtual TMetadata GetMetadata(Endpoint endpoint)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\EndpointSelector.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public abstract class EndpointSelector
	{
		public abstract Task SelectAsync(HttpContext httpContext, CandidateSet candidates);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\HostMatcherPolicy.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public sealed class HostMatcherPolicy : MatcherPolicy, IEndpointComparerPolicy, IEndpointSelectorPolicy, INodeBuilderPolicy
	{
		public IComparer<Endpoint> Comparer
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public override int Order
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
		{
			throw null;
		}

		public PolicyJumpTable BuildJumpTable(int exitDestination, IReadOnlyList<PolicyJumpTableEdge> edges)
		{
			throw null;
		}

		public IReadOnlyList<PolicyNodeEdge> GetEdges(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		bool IEndpointSelectorPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		bool INodeBuilderPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\HttpMethodMatcherPolicy.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public sealed class HttpMethodMatcherPolicy : MatcherPolicy, IEndpointComparerPolicy, IEndpointSelectorPolicy, INodeBuilderPolicy
	{
		internal readonly struct EdgeKey : IComparable, IComparable<EdgeKey>, IEquatable<EdgeKey>
		{
			public readonly bool IsCorsPreflightRequest;

			public readonly string HttpMethod;

			public EdgeKey(string httpMethod, bool isCorsPreflightRequest)
			{
				throw null;
			}

			public int CompareTo(EdgeKey other)
			{
				throw null;
			}

			public int CompareTo(object obj)
			{
				throw null;
			}

			public bool Equals(EdgeKey other)
			{
				throw null;
			}

			public override bool Equals(object obj)
			{
				throw null;
			}

			public override int GetHashCode()
			{
				throw null;
			}

			public override string ToString()
			{
				throw null;
			}
		}

		internal static readonly string AccessControlRequestMethod;

		internal const string AnyMethod = "*";

		internal const string Http405EndpointDisplayName = "405 HTTP Method Not Supported";

		internal static readonly string OriginHeader;

		internal static readonly string PreflightHttpMethod;

		public IComparer<Endpoint> Comparer
		{
			get
			{
				throw null;
			}
		}

		public override int Order
		{
			get
			{
				throw null;
			}
		}

		public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
		{
			throw null;
		}

		public PolicyJumpTable BuildJumpTable(int exitDestination, IReadOnlyList<PolicyJumpTableEdge> edges)
		{
			throw null;
		}

		public IReadOnlyList<PolicyNodeEdge> GetEdges(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		bool IEndpointSelectorPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		bool INodeBuilderPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\IEndpointComparerPolicy.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public interface IEndpointComparerPolicy
	{
		IComparer<Endpoint> Comparer
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\IEndpointSelectorPolicy.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public interface IEndpointSelectorPolicy
	{
		bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints);

		Task ApplyAsync(HttpContext httpContext, CandidateSet candidates);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\INodeBuilderPolicy.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public interface INodeBuilderPolicy
	{
		bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints);

		PolicyJumpTable BuildJumpTable(int exitDestination, IReadOnlyList<PolicyJumpTableEdge> edges);

		IReadOnlyList<PolicyNodeEdge> GetEdges(IReadOnlyList<Endpoint> endpoints);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\JumpTable.cs
using System.Diagnostics;

namespace Microsoft.AspNetCore.Routing.Matching
{
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	internal abstract class JumpTable
	{
		public virtual string DebuggerToString()
		{
			throw null;
		}

		public abstract int GetDestination(string path, PathSegment segment);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\Matcher.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Matching
{
	internal abstract class Matcher
	{
		public abstract Task MatchAsync(HttpContext httpContext);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\MatcherBuilder.cs
namespace Microsoft.AspNetCore.Routing.Matching
{
	internal abstract class MatcherBuilder
	{
		public abstract void AddEndpoint(RouteEndpoint endpoint);

		public abstract Matcher Build();
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\MatcherFactory.cs
namespace Microsoft.AspNetCore.Routing.Matching
{
	internal abstract class MatcherFactory
	{
		public abstract Matcher CreateMatcher(EndpointDataSource dataSource);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\PathSegment.cs
using System;

namespace Microsoft.AspNetCore.Routing.Matching
{
	internal readonly struct PathSegment : IEquatable<PathSegment>
	{
		public readonly int Start;

		public readonly int Length;

		public PathSegment(int start, int length)
		{
			throw null;
		}

		public bool Equals(PathSegment other)
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\PolicyJumpTable.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public abstract class PolicyJumpTable
	{
		public abstract int GetDestination(HttpContext httpContext);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\PolicyJumpTableEdge.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public readonly struct PolicyJumpTableEdge
	{
		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public int Destination
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object State
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public PolicyJumpTableEdge(object state, int destination)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\PolicyNodeEdge.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public readonly struct PolicyNodeEdge
	{
		private readonly object _dummy;

		public IReadOnlyList<Endpoint> Endpoints
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object State
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public PolicyNodeEdge(object state, IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePattern.cs
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public sealed class RoutePattern
	{
		public static readonly object RequiredValueAny;

		public IReadOnlyDictionary<string, object> Defaults
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public decimal InboundPrecedence
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public decimal OutboundPrecedence
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyDictionary<string, IReadOnlyList<RoutePatternParameterPolicyReference>> ParameterPolicies
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<RoutePatternParameterPart> Parameters
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<RoutePatternPathSegment> PathSegments
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string RawText
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyDictionary<string, object> RequiredValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RoutePattern()
		{
		}

		public RoutePatternParameterPart GetParameter(string name)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternException.cs
using System;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	public sealed class RoutePatternException : Exception
	{
		public string Pattern
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RoutePatternException(string pattern, string message)
		{
		}

		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternFactory.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	public static class RoutePatternFactory
	{
		public static RoutePatternParameterPolicyReference Constraint(IRouteConstraint constraint)
		{
			throw null;
		}

		public static RoutePatternParameterPolicyReference Constraint(object constraint)
		{
			throw null;
		}

		public static RoutePatternParameterPolicyReference Constraint(string constraint)
		{
			throw null;
		}

		public static RoutePatternLiteralPart LiteralPart(string content)
		{
			throw null;
		}

		public static RoutePatternParameterPart ParameterPart(string parameterName)
		{
			throw null;
		}

		public static RoutePatternParameterPart ParameterPart(string parameterName, object @default)
		{
			throw null;
		}

		public static RoutePatternParameterPart ParameterPart(string parameterName, object @default, RoutePatternParameterKind parameterKind)
		{
			throw null;
		}

		public static RoutePatternParameterPart ParameterPart(string parameterName, object @default, RoutePatternParameterKind parameterKind, params RoutePatternParameterPolicyReference[] parameterPolicies)
		{
			throw null;
		}

		public static RoutePatternParameterPart ParameterPart(string parameterName, object @default, RoutePatternParameterKind parameterKind, IEnumerable<RoutePatternParameterPolicyReference> parameterPolicies)
		{
			throw null;
		}

		public static RoutePatternParameterPolicyReference ParameterPolicy(IParameterPolicy parameterPolicy)
		{
			throw null;
		}

		public static RoutePatternParameterPolicyReference ParameterPolicy(string parameterPolicy)
		{
			throw null;
		}

		public static RoutePattern Parse(string pattern)
		{
			throw null;
		}

		public static RoutePattern Parse(string pattern, object defaults, object parameterPolicies)
		{
			throw null;
		}

		public static RoutePattern Parse(string pattern, object defaults, object parameterPolicies, object requiredValues)
		{
			throw null;
		}

		public static RoutePattern Pattern(params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(object defaults, object parameterPolicies, params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(object defaults, object parameterPolicies, IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string rawText, params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string rawText, IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string rawText, object defaults, object parameterPolicies, params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string rawText, object defaults, object parameterPolicies, IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePatternPathSegment Segment(params RoutePatternPart[] parts)
		{
			throw null;
		}

		public static RoutePatternPathSegment Segment(IEnumerable<RoutePatternPart> parts)
		{
			throw null;
		}

		public static RoutePatternSeparatorPart SeparatorPart(string content)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternLiteralPart.cs
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public sealed class RoutePatternLiteralPart : RoutePatternPart
	{
		public string Content
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RoutePatternLiteralPart()
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternParameterKind.cs
namespace Microsoft.AspNetCore.Routing.Patterns
{
	public enum RoutePatternParameterKind
	{
		Standard,
		Optional,
		CatchAll
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternParameterPart.cs
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public sealed class RoutePatternParameterPart : RoutePatternPart
	{
		public object Default
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool EncodeSlashes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsCatchAll
		{
			get
			{
				throw null;
			}
		}

		public bool IsOptional
		{
			get
			{
				throw null;
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RoutePatternParameterKind ParameterKind
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<RoutePatternParameterPolicyReference> ParameterPolicies
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RoutePatternParameterPart()
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternParameterPolicyReference.cs
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public sealed class RoutePatternParameterPolicyReference
	{
		public string Content
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IParameterPolicy ParameterPolicy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RoutePatternParameterPolicyReference()
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternPart.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	public abstract class RoutePatternPart
	{
		public bool IsLiteral
		{
			get
			{
				throw null;
			}
		}

		public bool IsParameter
		{
			get
			{
				throw null;
			}
		}

		public bool IsSeparator
		{
			get
			{
				throw null;
			}
		}

		public RoutePatternPartKind PartKind
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RoutePatternPart()
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternPartKind.cs
namespace Microsoft.AspNetCore.Routing.Patterns
{
	public enum RoutePatternPartKind
	{
		Literal,
		Parameter,
		Separator
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternPathSegment.cs
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	[DebuggerDisplay("{DebuggerToString()}")]
	[DebuggerDisplay("{DebuggerToString()}")]
	public sealed class RoutePatternPathSegment
	{
		public bool IsSimple
		{
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<RoutePatternPart> Parts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RoutePatternPathSegment()
		{
		}

		internal RoutePatternPathSegment(IReadOnlyList<RoutePatternPart> parts)
		{
		}

		internal string DebuggerToString()
		{
			throw null;
		}

		internal static string DebuggerToString(IReadOnlyList<RoutePatternPart> parts)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternSeparatorPart.cs
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public sealed class RoutePatternSeparatorPart : RoutePatternPart
	{
		public string Content
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal RoutePatternSeparatorPart()
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternTransformer.cs
namespace Microsoft.AspNetCore.Routing.Patterns
{
	public abstract class RoutePatternTransformer
	{
		public abstract RoutePattern SubstituteRequiredValues(RoutePattern original, object requiredValues);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\InlineConstraint.cs
using Microsoft.AspNetCore.Routing.Patterns;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Template
{
	public class InlineConstraint
	{
		public string Constraint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public InlineConstraint(RoutePatternParameterPolicyReference other)
		{
		}

		public InlineConstraint(string constraint)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\RoutePrecedence.cs
using Microsoft.AspNetCore.Routing.Patterns;

namespace Microsoft.AspNetCore.Routing.Template
{
	public static class RoutePrecedence
	{
		public static decimal ComputeInbound(RouteTemplate template)
		{
			throw null;
		}

		public static decimal ComputeOutbound(RouteTemplate template)
		{
			throw null;
		}

		internal static decimal ComputeInbound(RoutePattern routePattern)
		{
			throw null;
		}

		internal static decimal ComputeOutbound(RoutePattern routePattern)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\RouteTemplate.cs
using Microsoft.AspNetCore.Routing.Patterns;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Template
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public class RouteTemplate
	{
		public IList<TemplatePart> Parameters
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<TemplateSegment> Segments
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string TemplateText
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteTemplate(RoutePattern other)
		{
		}

		public RouteTemplate(string template, List<TemplateSegment> segments)
		{
		}

		public TemplatePart GetParameter(string name)
		{
			throw null;
		}

		public TemplateSegment GetSegment(int index)
		{
			throw null;
		}

		public RoutePattern ToRoutePattern()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\TemplateBinder.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.ObjectPool;
using System.Collections.Generic;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Routing.Template
{
	public class TemplateBinder
	{
		internal TemplateBinder()
		{
		}

		public string BindValues(RouteValueDictionary acceptedValues)
		{
			throw null;
		}

		public TemplateValuesResult GetValues(RouteValueDictionary ambientValues, RouteValueDictionary values)
		{
			throw null;
		}

		public static bool RoutePartsEqual(object a, object b)
		{
			throw null;
		}

		public bool TryProcessConstraints(HttpContext httpContext, RouteValueDictionary combinedValues, out string parameterName, out IRouteConstraint constraint)
		{
			throw null;
		}

		internal TemplateBinder(UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> pool, RoutePattern pattern, RouteValueDictionary defaults, IEnumerable<string> requiredKeys, IEnumerable<(string, IParameterPolicy)> parameterPolicies)
		{
		}

		internal TemplateBinder(UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> pool, RoutePattern pattern, IEnumerable<(string, IParameterPolicy)> parameterPolicies)
		{
		}

		internal TemplateBinder(UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> pool, RouteTemplate template, RouteValueDictionary defaults)
		{
		}

		internal bool TryBindValues(RouteValueDictionary acceptedValues, LinkOptions options, LinkOptions globalOptions, out (PathString path, QueryString query) result)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\TemplateBinderFactory.cs
using Microsoft.AspNetCore.Routing.Patterns;

namespace Microsoft.AspNetCore.Routing.Template
{
	public abstract class TemplateBinderFactory
	{
		public abstract TemplateBinder Create(RoutePattern pattern);

		public abstract TemplateBinder Create(RouteTemplate template, RouteValueDictionary defaults);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\TemplateMatcher.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Template
{
	public class TemplateMatcher
	{
		public RouteValueDictionary Defaults
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteTemplate Template
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TemplateMatcher(RouteTemplate template, RouteValueDictionary defaults)
		{
		}

		public bool TryMatch(PathString path, RouteValueDictionary values)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\TemplateParser.cs
namespace Microsoft.AspNetCore.Routing.Template
{
	public static class TemplateParser
	{
		public static RouteTemplate Parse(string routeTemplate)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\TemplatePart.cs
using Microsoft.AspNetCore.Routing.Patterns;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Template
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public class TemplatePart
	{
		public object DefaultValue
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IEnumerable<InlineConstraint> InlineConstraints
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsCatchAll
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsLiteral
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsOptional
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsOptionalSeperator
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool IsParameter
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Text
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TemplatePart()
		{
		}

		public TemplatePart(RoutePatternPart other)
		{
		}

		public static TemplatePart CreateLiteral(string text)
		{
			throw null;
		}

		public static TemplatePart CreateParameter(string name, bool isCatchAll, bool isOptional, object defaultValue, IEnumerable<InlineConstraint> inlineConstraints)
		{
			throw null;
		}

		public RoutePatternPart ToRoutePatternPart()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\TemplateSegment.cs
using Microsoft.AspNetCore.Routing.Patterns;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Template
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public class TemplateSegment
	{
		public bool IsSimple
		{
			get
			{
				throw null;
			}
		}

		public List<TemplatePart> Parts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TemplateSegment()
		{
		}

		public TemplateSegment(RoutePatternPathSegment other)
		{
		}

		public RoutePatternPathSegment ToRoutePatternPathSegment()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Template\TemplateValuesResult.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Template
{
	public class TemplateValuesResult
	{
		public RouteValueDictionary AcceptedValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteValueDictionary CombinedValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\InboundMatch.cs
using Microsoft.AspNetCore.Routing.Template;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	public class InboundMatch
	{
		public InboundRouteEntry Entry
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TemplateMatcher TemplateMatcher
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\InboundRouteEntry.cs
using Microsoft.AspNetCore.Routing.Template;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	public class InboundRouteEntry
	{
		public IDictionary<string, IRouteConstraint> Constraints
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteValueDictionary Defaults
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IRouter Handler
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int Order
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public decimal Precedence
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string RouteName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteTemplate RouteTemplate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\OutboundMatch.cs
using Microsoft.AspNetCore.Routing.Template;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	public class OutboundMatch
	{
		public OutboundRouteEntry Entry
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TemplateBinder TemplateBinder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\OutboundMatchResult.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	internal readonly struct OutboundMatchResult
	{
		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public bool IsFallbackMatch
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public OutboundMatch Match
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public OutboundMatchResult(OutboundMatch match, bool isFallbackMatch)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\OutboundRouteEntry.cs
using Microsoft.AspNetCore.Routing.Template;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	public class OutboundRouteEntry
	{
		public IDictionary<string, IRouteConstraint> Constraints
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public object Data
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteValueDictionary Defaults
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IRouter Handler
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int Order
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public decimal Precedence
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteValueDictionary RequiredLinkValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string RouteName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public RouteTemplate RouteTemplate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\TreeRouteBuilder.cs
using Microsoft.AspNetCore.Routing.Template;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	public class TreeRouteBuilder
	{
		public IList<InboundRouteEntry> InboundEntries
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<OutboundRouteEntry> OutboundEntries
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal TreeRouteBuilder()
		{
		}

		public TreeRouter Build()
		{
			throw null;
		}

		public TreeRouter Build(int version)
		{
			throw null;
		}

		public void Clear()
		{
		}

		public InboundRouteEntry MapInbound(IRouter handler, RouteTemplate routeTemplate, string routeName, int order)
		{
			throw null;
		}

		public OutboundRouteEntry MapOutbound(IRouter handler, RouteTemplate routeTemplate, RouteValueDictionary requiredLinkValues, string routeName, int order)
		{
			throw null;
		}

		internal TreeRouteBuilder(ILoggerFactory loggerFactory, ObjectPool<UriBuildingContext> objectPool, IInlineConstraintResolver constraintResolver)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\TreeRouter.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Tree
{
	public class TreeRouter : IRouter
	{
		public static readonly string RouteGroupKey;

		public int Version
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal IEnumerable<UrlMatchingTree> MatchingTrees
		{
			get
			{
				throw null;
			}
		}

		internal TreeRouter()
		{
		}

		public VirtualPathData GetVirtualPath(VirtualPathContext context)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task RouteAsync(RouteContext context)
		{
			throw null;
		}

		internal TreeRouter(UrlMatchingTree[] trees, IEnumerable<OutboundRouteEntry> linkGenerationEntries, UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> objectPool, ILogger routeLogger, ILogger constraintLogger, int version)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\UrlMatchingNode.cs
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	public class UrlMatchingNode
	{
		public UrlMatchingNode CatchAlls
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public UrlMatchingNode ConstrainedCatchAlls
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public UrlMatchingNode ConstrainedParameters
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int Depth
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsCatchAll
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Dictionary<string, UrlMatchingNode> Literals
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public List<InboundMatch> Matches
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public UrlMatchingNode Parameters
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public UrlMatchingNode(int length)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\UrlMatchingTree.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	public class UrlMatchingTree
	{
		public int Order
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public UrlMatchingNode Root
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public UrlMatchingTree(int order)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.Extensions.DependencyInjection\RoutingServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Routing;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class RoutingServiceCollectionExtensions
	{
		public static IServiceCollection AddRouting(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddRouting(this IServiceCollection services, Action<RouteOptions> configureOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.Extensions.Internal\HashCodeCombiner.cs
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Internal
{
	internal struct HashCodeCombiner
	{
		private long _combinedHash64;

		public int CombinedHash
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				return _combinedHash64.GetHashCode();
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private HashCodeCombiner(long seed)
		{
			_combinedHash64 = seed;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(IEnumerable e)
		{
			if (e == null)
			{
				Add(0);
				return;
			}
			int num = 0;
			foreach (object? item in e)
			{
				Add(item);
				num++;
			}
			Add(num);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static implicit operator int(HashCodeCombiner self)
		{
			return self.CombinedHash;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(int i)
		{
			_combinedHash64 = (((_combinedHash64 << 5) + _combinedHash64) ^ i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(string s)
		{
			int i = s?.GetHashCode() ?? 0;
			Add(i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(object o)
		{
			int i = o?.GetHashCode() ?? 0;
			Add(i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add<TValue>(TValue value, IEqualityComparer<TValue> comparer)
		{
			int i = (value != null) ? comparer.GetHashCode(value) : 0;
			Add(i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static HashCodeCombiner Start()
		{
			return new HashCodeCombiner(5381L);
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IOutboundParameterTransformer.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IOutboundParameterTransformer : IParameterPolicy
	{
		string TransformOutbound(object value);
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IParameterPolicy.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IParameterPolicy
	{
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public interface IRouteConstraint : IParameterPolicy
	{
		bool Match(HttpContext httpContext, IRouter route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection);
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IRouteHandler.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public interface IRouteHandler
	{
		RequestDelegate GetRequestHandler(HttpContext httpContext, RouteData routeData);
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IRouter.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public interface IRouter
	{
		VirtualPathData GetVirtualPath(VirtualPathContext context);

		Task RouteAsync(RouteContext context);
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IRoutingFeature.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IRoutingFeature
	{
		RouteData RouteData
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\LinkGenerator.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public abstract class LinkGenerator
	{
		public abstract string GetPathByAddress<TAddress>(HttpContext httpContext, TAddress address, RouteValueDictionary values, RouteValueDictionary ambientValues = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions options = null);

		public abstract string GetPathByAddress<TAddress>(TAddress address, RouteValueDictionary values, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions options = null);

		public abstract string GetUriByAddress<TAddress>(HttpContext httpContext, TAddress address, RouteValueDictionary values, RouteValueDictionary ambientValues = null, string scheme = null, HostString? host = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions options = null);

		public abstract string GetUriByAddress<TAddress>(TAddress address, RouteValueDictionary values, string scheme, HostString host, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions options = null);
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\LinkOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class LinkOptions
	{
		public bool? AppendTrailingSlash
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool? LowercaseQueryStrings
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool? LowercaseUrls
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\RouteContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteContext
	{
		public RequestDelegate Handler
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public HttpContext HttpContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteData RouteData
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public RouteContext(HttpContext httpContext)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\RouteData.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteData
	{
		public readonly struct RouteDataSnapshot
		{
			private readonly object _dummy;

			public RouteDataSnapshot(RouteData routeData, RouteValueDictionary dataTokens, IList<IRouter> routers, RouteValueDictionary values)
			{
				throw null;
			}

			public void Restore()
			{
			}
		}

		public RouteValueDictionary DataTokens
		{
			get
			{
				throw null;
			}
		}

		public IList<IRouter> Routers
		{
			get
			{
				throw null;
			}
		}

		public RouteValueDictionary Values
		{
			get
			{
				throw null;
			}
		}

		public RouteData()
		{
		}

		public RouteData(RouteData other)
		{
		}

		public RouteData(RouteValueDictionary values)
		{
		}

		public RouteDataSnapshot PushState(IRouter router, RouteValueDictionary values, RouteValueDictionary dataTokens)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\RouteDirection.cs
namespace Microsoft.AspNetCore.Routing
{
	public enum RouteDirection
	{
		IncomingRequest,
		UrlGeneration
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\RoutingHttpContextExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public static class RoutingHttpContextExtensions
	{
		public static RouteData GetRouteData(this HttpContext httpContext)
		{
			throw null;
		}

		public static object GetRouteValue(this HttpContext httpContext, string key)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\VirtualPathContext.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class VirtualPathContext
	{
		public RouteValueDictionary AmbientValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HttpContext HttpContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string RouteName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteValueDictionary Values
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public VirtualPathContext(HttpContext httpContext, RouteValueDictionary ambientValues, RouteValueDictionary values)
		{
		}

		public VirtualPathContext(HttpContext httpContext, RouteValueDictionary ambientValues, RouteValueDictionary values, string routeName)
		{
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\VirtualPathData.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class VirtualPathData
	{
		public RouteValueDictionary DataTokens
		{
			get
			{
				throw null;
			}
		}

		public IRouter Router
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string VirtualPath
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public VirtualPathData(IRouter router, string virtualPath)
		{
		}

		public VirtualPathData(IRouter router, string virtualPath, RouteValueDictionary dataTokens)
		{
		}
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Builder\SessionMiddlewareExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class SessionMiddlewareExtensions
	{
		public static IApplicationBuilder UseSession(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseSession(this IApplicationBuilder app, SessionOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Builder\SessionOptions.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class SessionOptions
	{
		public CookieBuilder Cookie
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public TimeSpan IdleTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan IOTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Session\DistributedSession.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Session
{
	public class DistributedSession : ISession
	{
		public string Id
		{
			get
			{
				throw null;
			}
		}

		public bool IsAvailable
		{
			get
			{
				throw null;
			}
		}

		public IEnumerable<string> Keys
		{
			get
			{
				throw null;
			}
		}

		public DistributedSession(IDistributedCache cache, string sessionKey, TimeSpan idleTimeout, TimeSpan ioTimeout, Func<bool> tryEstablishSession, ILoggerFactory loggerFactory, bool isNewSessionKey)
		{
		}

		public void Clear()
		{
		}

		[DebuggerStepThrough]
		public Task CommitAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task LoadAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public void Remove(string key)
		{
		}

		public void Set(string key, byte[] value)
		{
		}

		public bool TryGetValue(string key, out byte[] value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Session\DistributedSessionStore.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System;

namespace Microsoft.AspNetCore.Session
{
	public class DistributedSessionStore : ISessionStore
	{
		public DistributedSessionStore(IDistributedCache cache, ILoggerFactory loggerFactory)
		{
		}

		public ISession Create(string sessionKey, TimeSpan idleTimeout, TimeSpan ioTimeout, Func<bool> tryEstablishSession, bool isNewSessionKey)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Session\ISessionStore.cs
using Microsoft.AspNetCore.Http;
using System;

namespace Microsoft.AspNetCore.Session
{
	public interface ISessionStore
	{
		ISession Create(string sessionKey, TimeSpan idleTimeout, TimeSpan ioTimeout, Func<bool> tryEstablishSession, bool isNewSessionKey);
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Session\SessionDefaults.cs
namespace Microsoft.AspNetCore.Session
{
	public static class SessionDefaults
	{
		public static readonly string CookieName;

		public static readonly string CookiePath;
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Session\SessionFeature.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Session
{
	public class SessionFeature : ISessionFeature
	{
		public ISession Session
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.Session\Microsoft.AspNetCore.Session\SessionMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Session
{
	public class SessionMiddleware
	{
		public SessionMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IDataProtectionProvider dataProtectionProvider, ISessionStore sessionStore, IOptions<SessionOptions> options)
		{
		}

		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Session\Microsoft.Extensions.DependencyInjection\SessionServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Builder;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class SessionServiceCollectionExtensions
	{
		public static IServiceCollection AddSession(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddSession(this IServiceCollection services, Action<SessionOptions> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.AspNetCore.Builder\HubEndpointConventionBuilder.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public sealed class HubEndpointConventionBuilder : IEndpointConventionBuilder, IHubEndpointConventionBuilder
	{
		internal HubEndpointConventionBuilder()
		{
		}

		public void Add(Action<EndpointBuilder> convention)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.AspNetCore.Builder\HubEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.SignalR;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class HubEndpointRouteBuilderExtensions
	{
		public static HubEndpointConventionBuilder MapHub<THub>(this IEndpointRouteBuilder endpoints, string pattern) where THub : Hub
		{
			throw null;
		}

		public static HubEndpointConventionBuilder MapHub<THub>(this IEndpointRouteBuilder endpoints, string pattern, Action<HttpConnectionDispatcherOptions> configureOptions) where THub : Hub
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.AspNetCore.Builder\IHubEndpointConventionBuilder.cs
namespace Microsoft.AspNetCore.Builder
{
	public interface IHubEndpointConventionBuilder : IEndpointConventionBuilder
	{
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.AspNetCore.Builder\SignalRAppBuilderExtensions.cs
using Microsoft.AspNetCore.SignalR;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class SignalRAppBuilderExtensions
	{
		[Obsolete("This method is obsolete and will be removed in a future version. The recommended alternative is to use MapHub<THub> inside Microsoft.AspNetCore.Builder.UseEndpoints(...).")]
		public static IApplicationBuilder UseSignalR(this IApplicationBuilder app, Action<HubRouteBuilder> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.AspNetCore.SignalR\GetHttpContextExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.SignalR
{
	public static class GetHttpContextExtensions
	{
		public static HttpContext GetHttpContext(this HubCallerContext connection)
		{
			throw null;
		}

		public static HttpContext GetHttpContext(this HubConnectionContext connection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.AspNetCore.SignalR\HubRouteBuilder.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Connections;
using System;

namespace Microsoft.AspNetCore.SignalR
{
	[Obsolete("This class is obsolete and will be removed in a future version. The recommended alternative is to use MapHub<THub> inside Microsoft.AspNetCore.Builder.UseEndpoints(...).")]
	public class HubRouteBuilder
	{
		public HubRouteBuilder(ConnectionsRouteBuilder routes)
		{
		}

		public void MapHub<THub>(PathString path) where THub : Hub
		{
		}

		public void MapHub<THub>(PathString path, Action<HttpConnectionDispatcherOptions> configureOptions) where THub : Hub
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.Extensions.DependencyInjection\SignalRDependencyInjectionExtensions.cs
using Microsoft.AspNetCore.SignalR;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class SignalRDependencyInjectionExtensions
	{
		public static ISignalRServerBuilder AddHubOptions<THub>(this ISignalRServerBuilder signalrBuilder, Action<HubOptions<THub>> configure) where THub : Hub
		{
			throw null;
		}

		public static ISignalRServerBuilder AddSignalR(this IServiceCollection services)
		{
			throw null;
		}

		public static ISignalRServerBuilder AddSignalR(this IServiceCollection services, Action<HubOptions> configure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR\HubException.cs
using System;
using System.Runtime.Serialization;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubException : Exception
	{
		public HubException()
		{
		}

		public HubException(SerializationInfo info, StreamingContext context)
		{
		}

		public HubException(string message)
		{
		}

		public HubException(string message, Exception innerException)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR\IInvocationBinder.cs
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.SignalR
{
	public interface IInvocationBinder
	{
		IReadOnlyList<Type> GetParameterTypes(string methodName);

		Type GetReturnType(string invocationId);

		Type GetStreamItemType(string streamId);
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR\ISignalRBuilder.cs
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.SignalR
{
	public interface ISignalRBuilder
	{
		IServiceCollection Services
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\CancelInvocationMessage.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class CancelInvocationMessage : HubInvocationMessage
	{
		public CancelInvocationMessage(string invocationId)
			: base(null)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\CloseMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class CloseMessage : HubMessage
	{
		public static readonly CloseMessage Empty;

		public bool AllowReconnect
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CloseMessage(string error)
		{
		}

		public CloseMessage(string error, bool allowReconnect)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\CompletionMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class CompletionMessage : HubInvocationMessage
	{
		public string Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool HasResult
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object Result
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CompletionMessage(string invocationId, string error, object result, bool hasResult)
			: base(null)
		{
		}

		public static CompletionMessage Empty(string invocationId)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}

		public static CompletionMessage WithError(string invocationId, string error)
		{
			throw null;
		}

		public static CompletionMessage WithResult(string invocationId, object payload)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HandshakeProtocol.cs
using System;
using System.Buffers;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public static class HandshakeProtocol
	{
		public static ReadOnlySpan<byte> GetSuccessfulHandshake(IHubProtocol protocol)
		{
			throw null;
		}

		public static bool TryParseRequestMessage(ref ReadOnlySequence<byte> buffer, out HandshakeRequestMessage requestMessage)
		{
			throw null;
		}

		public static bool TryParseResponseMessage(ref ReadOnlySequence<byte> buffer, out HandshakeResponseMessage responseMessage)
		{
			throw null;
		}

		public static void WriteRequestMessage(HandshakeRequestMessage requestMessage, IBufferWriter<byte> output)
		{
		}

		public static void WriteResponseMessage(HandshakeResponseMessage responseMessage, IBufferWriter<byte> output)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HandshakeRequestMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class HandshakeRequestMessage : HubMessage
	{
		public string Protocol
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int Version
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HandshakeRequestMessage(string protocol, int version)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HandshakeResponseMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class HandshakeResponseMessage : HubMessage
	{
		public static readonly HandshakeResponseMessage Empty;

		public string Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HandshakeResponseMessage(string error)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubInvocationMessage.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public abstract class HubInvocationMessage : HubMessage
	{
		public IDictionary<string, string> Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string InvocationId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HubInvocationMessage(string invocationId)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubMessage.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public abstract class HubMessage
	{
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubMethodInvocationMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public abstract class HubMethodInvocationMessage : HubInvocationMessage
	{
		public object[] Arguments
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string[] StreamIds
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Target
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HubMethodInvocationMessage(string invocationId, string target, object[] arguments)
			: base(null)
		{
		}

		protected HubMethodInvocationMessage(string invocationId, string target, object[] arguments, string[] streamIds)
			: base(null)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubProtocolConstants.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public static class HubProtocolConstants
	{
		public const int CancelInvocationMessageType = 5;

		public const int CloseMessageType = 7;

		public const int CompletionMessageType = 3;

		public const int InvocationMessageType = 1;

		public const int PingMessageType = 6;

		public const int StreamInvocationMessageType = 4;

		public const int StreamItemMessageType = 2;
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubProtocolExtensions.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public static class HubProtocolExtensions
	{
		public static byte[] GetMessageBytes(this IHubProtocol hubProtocol, HubMessage message)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\IHubProtocol.cs
using Microsoft.AspNetCore.Connections;
using System;
using System.Buffers;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public interface IHubProtocol
	{
		string Name
		{
			get;
		}

		TransferFormat TransferFormat
		{
			get;
		}

		int Version
		{
			get;
		}

		ReadOnlyMemory<byte> GetMessageBytes(HubMessage message);

		bool IsVersionSupported(int version);

		bool TryParseMessage(ref ReadOnlySequence<byte> input, IInvocationBinder binder, out HubMessage message);

		void WriteMessage(HubMessage message, IBufferWriter<byte> output);
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\InvocationBindingFailureMessage.cs
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class InvocationBindingFailureMessage : HubInvocationMessage
	{
		public ExceptionDispatchInfo BindingFailure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Target
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public InvocationBindingFailureMessage(string invocationId, string target, ExceptionDispatchInfo bindingFailure)
			: base(null)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\InvocationMessage.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class InvocationMessage : HubMethodInvocationMessage
	{
		public InvocationMessage(string target, object[] arguments)
			: base(null, null, null, null)
		{
		}

		public InvocationMessage(string invocationId, string target, object[] arguments)
			: base(null, null, null, null)
		{
		}

		public InvocationMessage(string invocationId, string target, object[] arguments, string[] streamIds)
			: base(null, null, null, null)
		{
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\PingMessage.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class PingMessage : HubMessage
	{
		public static readonly PingMessage Instance;

		internal PingMessage()
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\StreamBindingFailureMessage.cs
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class StreamBindingFailureMessage : HubMessage
	{
		public ExceptionDispatchInfo BindingFailure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Id
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public StreamBindingFailureMessage(string id, ExceptionDispatchInfo bindingFailure)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\StreamInvocationMessage.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class StreamInvocationMessage : HubMethodInvocationMessage
	{
		public StreamInvocationMessage(string invocationId, string target, object[] arguments)
			: base(null, null, null, null)
		{
		}

		public StreamInvocationMessage(string invocationId, string target, object[] arguments, string[] streamIds)
			: base(null, null, null, null)
		{
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\StreamItemMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class StreamItemMessage : HubInvocationMessage
	{
		public object Item
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public StreamItemMessage(string invocationId, object item)
			: base(null)
		{
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\ClientProxyExtensions.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public static class ClientProxyExtensions
	{
		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, object arg4, object arg5, object arg6, object arg7, object arg8, object arg9, object arg10, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, object arg4, object arg5, object arg6, object arg7, object arg8, object arg9, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, object arg4, object arg5, object arg6, object arg7, object arg8, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, object arg4, object arg5, object arg6, object arg7, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, object arg4, object arg5, object arg6, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, object arg4, object arg5, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, object arg4, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, object arg3, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, object arg2, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object arg1, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\DefaultHubLifetimeManager.cs
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public class DefaultHubLifetimeManager<THub> : HubLifetimeManager<THub> where THub : Hub
	{
		public DefaultHubLifetimeManager(ILogger<DefaultHubLifetimeManager<THub>> logger)
		{
		}

		public override Task AddToGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task OnConnectedAsync(HubConnectionContext connection)
		{
			throw null;
		}

		public override Task OnDisconnectedAsync(HubConnectionContext connection)
		{
			throw null;
		}

		public override Task RemoveFromGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendAllAsync(string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendAllExceptAsync(string methodName, object[] args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendConnectionAsync(string connectionId, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendConnectionsAsync(IReadOnlyList<string> connectionIds, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendGroupAsync(string groupName, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendGroupExceptAsync(string groupName, string methodName, object[] args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendGroupsAsync(IReadOnlyList<string> groupNames, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendUserAsync(string userId, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendUsersAsync(IReadOnlyList<string> userIds, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\DefaultUserIdProvider.cs
namespace Microsoft.AspNetCore.SignalR
{
	public class DefaultUserIdProvider : IUserIdProvider
	{
		public virtual string GetUserId(HubConnectionContext connection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\DynamicHub.cs
namespace Microsoft.AspNetCore.SignalR
{
	public abstract class DynamicHub : Hub
	{
		public new DynamicHubClients Clients
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\DynamicHubClients.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.SignalR
{
	public class DynamicHubClients
	{
		public dynamic All
		{
			get
			{
				throw null;
			}
		}

		public dynamic Caller
		{
			get
			{
				throw null;
			}
		}

		public dynamic Others
		{
			get
			{
				throw null;
			}
		}

		public DynamicHubClients(IHubCallerClients clients)
		{
		}

		public dynamic AllExcept(IReadOnlyList<string> excludedConnectionIds)
		{
			throw null;
		}

		public dynamic Client(string connectionId)
		{
			throw null;
		}

		public dynamic Clients(IReadOnlyList<string> connectionIds)
		{
			throw null;
		}

		public dynamic Group(string groupName)
		{
			throw null;
		}

		public dynamic GroupExcept(string groupName, IReadOnlyList<string> excludedConnectionIds)
		{
			throw null;
		}

		public dynamic Groups(IReadOnlyList<string> groupNames)
		{
			throw null;
		}

		public dynamic OthersInGroup(string groupName)
		{
			throw null;
		}

		public dynamic User(string userId)
		{
			throw null;
		}

		public dynamic Users(IReadOnlyList<string> userIds)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\Hub.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public abstract class Hub : IDisposable
	{
		public IHubCallerClients Clients
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public HubCallerContext Context
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IGroupManager Groups
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public void Dispose()
		{
		}

		protected virtual void Dispose(bool disposing)
		{
		}

		public virtual Task OnConnectedAsync()
		{
			throw null;
		}

		public virtual Task OnDisconnectedAsync(Exception exception)
		{
			throw null;
		}
	}
	public abstract class Hub<T> : Hub where T : class
	{
		public new IHubCallerClients<T> Clients
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubCallerContext.cs
using Microsoft.AspNetCore.Http.Features;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;

namespace Microsoft.AspNetCore.SignalR
{
	public abstract class HubCallerContext
	{
		public abstract CancellationToken ConnectionAborted
		{
			get;
		}

		public abstract string ConnectionId
		{
			get;
		}

		public abstract IFeatureCollection Features
		{
			get;
		}

		public abstract IDictionary<object, object> Items
		{
			get;
		}

		public abstract ClaimsPrincipal User
		{
			get;
		}

		public abstract string UserIdentifier
		{
			get;
		}

		public abstract void Abort();
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubClientsExtensions.cs
namespace Microsoft.AspNetCore.SignalR
{
	public static class HubClientsExtensions
	{
		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1)
		{
			throw null;
		}

		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1, string excludedConnectionId2)
		{
			throw null;
		}

		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3)
		{
			throw null;
		}

		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4)
		{
			throw null;
		}

		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5)
		{
			throw null;
		}

		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5, string excludedConnectionId6)
		{
			throw null;
		}

		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5, string excludedConnectionId6, string excludedConnectionId7)
		{
			throw null;
		}

		public static T AllExcept<T>(this IHubClients<T> hubClients, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5, string excludedConnectionId6, string excludedConnectionId7, string excludedConnectionId8)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1, string connection2)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1, string connection2, string connection3)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1, string connection2, string connection3, string connection4)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1, string connection2, string connection3, string connection4, string connection5)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1, string connection2, string connection3, string connection4, string connection5, string connection6)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1, string connection2, string connection3, string connection4, string connection5, string connection6, string connection7)
		{
			throw null;
		}

		public static T Clients<T>(this IHubClients<T> hubClients, string connection1, string connection2, string connection3, string connection4, string connection5, string connection6, string connection7, string connection8)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1, string excludedConnectionId2)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5, string excludedConnectionId6)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5, string excludedConnectionId6, string excludedConnectionId7)
		{
			throw null;
		}

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, string excludedConnectionId1, string excludedConnectionId2, string excludedConnectionId3, string excludedConnectionId4, string excludedConnectionId5, string excludedConnectionId6, string excludedConnectionId7, string excludedConnectionId8)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1, string group2)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1, string group2, string group3)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1, string group2, string group3, string group4)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1, string group2, string group3, string group4, string group5)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1, string group2, string group3, string group4, string group5, string group6)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1, string group2, string group3, string group4, string group5, string group6, string group7)
		{
			throw null;
		}

		public static T Groups<T>(this IHubClients<T> hubClients, string group1, string group2, string group3, string group4, string group5, string group6, string group7, string group8)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1, string user2)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1, string user2, string user3)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1, string user2, string user3, string user4)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1, string user2, string user3, string user4, string user5)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1, string user2, string user3, string user4, string user5, string user6)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1, string user2, string user3, string user4, string user5, string user6, string user7)
		{
			throw null;
		}

		public static T Users<T>(this IHubClients<T> hubClients, string user1, string user2, string user3, string user4, string user5, string user6, string user7, string user8)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubConnectionContext.cs
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.SignalR.Protocol;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubConnectionContext
	{
		public virtual CancellationToken ConnectionAborted
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public virtual string ConnectionId
		{
			get
			{
				throw null;
			}
		}

		public virtual IFeatureCollection Features
		{
			get
			{
				throw null;
			}
		}

		public virtual IDictionary<object, object> Items
		{
			get
			{
				throw null;
			}
		}

		public virtual IHubProtocol Protocol
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public virtual ClaimsPrincipal User
		{
			get
			{
				throw null;
			}
		}

		public string UserIdentifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public HubConnectionContext(ConnectionContext connectionContext, HubConnectionContextOptions contextOptions, ILoggerFactory loggerFactory)
		{
		}

		public virtual void Abort()
		{
		}

		public virtual ValueTask WriteAsync(HubMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public virtual ValueTask WriteAsync(SerializedHubMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubConnectionContextOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubConnectionContextOptions
	{
		public TimeSpan ClientTimeoutInterval
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan KeepAliveInterval
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long? MaximumReceiveMessageSize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int StreamBufferCapacity
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubConnectionHandler.cs
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubConnectionHandler<THub> : ConnectionHandler where THub : Hub
	{
		public HubConnectionHandler(HubLifetimeManager<THub> lifetimeManager, IHubProtocolResolver protocolResolver, IOptions<HubOptions> globalHubOptions, IOptions<HubOptions<THub>> hubOptions, ILoggerFactory loggerFactory, IUserIdProvider userIdProvider, IServiceScopeFactory serviceScopeFactory)
		{
		}

		[DebuggerStepThrough]
		public override Task OnConnectedAsync(ConnectionContext connection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubConnectionStore.cs
using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubConnectionStore
	{
		public readonly struct Enumerator : IEnumerator<HubConnectionContext>, IEnumerator, IDisposable
		{
			private readonly object _dummy;

			public HubConnectionContext Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				get
				{
					throw null;
				}
			}

			public Enumerator(HubConnectionStore hubConnectionList)
			{
				throw null;
			}

			public void Dispose()
			{
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Reset()
			{
			}
		}

		public int Count
		{
			get
			{
				throw null;
			}
		}

		public HubConnectionContext this[string connectionId]
		{
			get
			{
				throw null;
			}
		}

		public void Add(HubConnectionContext connection)
		{
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		public void Remove(HubConnectionContext connection)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubInvocationContext.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubInvocationContext
	{
		public HubCallerContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<object> HubMethodArguments
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string HubMethodName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HubInvocationContext(HubCallerContext context, string hubMethodName, object[] hubMethodArguments)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubLifetimeManager.cs
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public abstract class HubLifetimeManager<THub> where THub : Hub
	{
		public abstract Task AddToGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task OnConnectedAsync(HubConnectionContext connection);

		public abstract Task OnDisconnectedAsync(HubConnectionContext connection);

		public abstract Task RemoveFromGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendAllAsync(string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendAllExceptAsync(string methodName, object[] args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendConnectionAsync(string connectionId, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendConnectionsAsync(IReadOnlyList<string> connectionIds, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendGroupAsync(string groupName, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendGroupExceptAsync(string groupName, string methodName, object[] args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendGroupsAsync(IReadOnlyList<string> groupNames, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendUserAsync(string userId, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendUsersAsync(IReadOnlyList<string> userIds, string methodName, object[] args, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubMetadata.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubMetadata
	{
		public Type HubType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HubMetadata(Type hubType)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubMethodNameAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
	public class HubMethodNameAttribute : Attribute
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HubMethodNameAttribute(string name)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubOptions.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubOptions
	{
		public TimeSpan? ClientTimeoutInterval
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public bool? EnableDetailedErrors
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan? HandshakeTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public TimeSpan? KeepAliveInterval
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public long? MaximumReceiveMessageSize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int? StreamBufferCapacity
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IList<string> SupportedProtocols
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
	public class HubOptions<THub> : HubOptions where THub : Hub
	{
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubOptionsSetup.cs
using Microsoft.AspNetCore.SignalR.Protocol;
using Microsoft.Extensions.Options;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubOptionsSetup : IConfigureOptions<HubOptions>
	{
		public HubOptionsSetup(IEnumerable<IHubProtocol> protocols)
		{
		}

		public void Configure(HubOptions options)
		{
		}
	}
	public class HubOptionsSetup<THub> : IConfigureOptions<HubOptions<THub>> where THub : Hub
	{
		public HubOptionsSetup(IOptions<HubOptions> options)
		{
		}

		public void Configure(HubOptions<THub> options)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IClientProxy.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public interface IClientProxy
	{
		Task SendCoreAsync(string method, object[] args, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IGroupManager.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public interface IGroupManager
	{
		Task AddToGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken));

		Task RemoveFromGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IHubActivator.cs
namespace Microsoft.AspNetCore.SignalR
{
	public interface IHubActivator<THub> where THub : Hub
	{
		THub Create();

		void Release(THub hub);
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IHubCallerClients.cs
namespace Microsoft.AspNetCore.SignalR
{
	public interface IHubCallerClients : IHubCallerClients<IClientProxy>, IHubClients<IClientProxy>
	{
	}
	public interface IHubCallerClients<T> : IHubClients<T>
	{
		T Caller
		{
			get;
		}

		T Others
		{
			get;
		}

		T OthersInGroup(string groupName);
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IHubClients.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.SignalR
{
	public interface IHubClients : IHubClients<IClientProxy>
	{
	}
	public interface IHubClients<T>
	{
		T All
		{
			get;
		}

		T AllExcept(IReadOnlyList<string> excludedConnectionIds);

		T Client(string connectionId);

		T Clients(IReadOnlyList<string> connectionIds);

		T Group(string groupName);

		T GroupExcept(string groupName, IReadOnlyList<string> excludedConnectionIds);

		T Groups(IReadOnlyList<string> groupNames);

		T User(string userId);

		T Users(IReadOnlyList<string> userIds);
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IHubContext.cs
namespace Microsoft.AspNetCore.SignalR
{
	public interface IHubContext<THub> where THub : Hub
	{
		IHubClients Clients
		{
			get;
		}

		IGroupManager Groups
		{
			get;
		}
	}
	public interface IHubContext<THub, T> where THub : Hub<T> where T : class
	{
		IHubClients<T> Clients
		{
			get;
		}

		IGroupManager Groups
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IHubProtocolResolver.cs
using Microsoft.AspNetCore.SignalR.Protocol;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.SignalR
{
	public interface IHubProtocolResolver
	{
		IReadOnlyList<IHubProtocol> AllProtocols
		{
			get;
		}

		IHubProtocol GetProtocol(string protocolName, IReadOnlyList<string> supportedProtocols);
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\ISignalRServerBuilder.cs
namespace Microsoft.AspNetCore.SignalR
{
	public interface ISignalRServerBuilder : ISignalRBuilder
	{
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IUserIdProvider.cs
namespace Microsoft.AspNetCore.SignalR
{
	public interface IUserIdProvider
	{
		string GetUserId(HubConnectionContext connection);
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\SerializedHubMessage.cs
using Microsoft.AspNetCore.SignalR.Protocol;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public class SerializedHubMessage
	{
		public HubMessage Message
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public SerializedHubMessage(HubMessage message)
		{
		}

		public SerializedHubMessage(IReadOnlyList<SerializedMessage> messages)
		{
		}

		public ReadOnlyMemory<byte> GetSerializedMessage(IHubProtocol protocol)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\SerializedMessage.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public readonly struct SerializedMessage
	{
		private readonly object _dummy;

		public string ProtocolName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ReadOnlyMemory<byte> Serialized
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public SerializedMessage(string protocolName, ReadOnlyMemory<byte> serialized)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\SignalRConnectionBuilderExtensions.cs
using Microsoft.AspNetCore.Connections;

namespace Microsoft.AspNetCore.SignalR
{
	public static class SignalRConnectionBuilderExtensions
	{
		public static IConnectionBuilder UseHub<THub>(this IConnectionBuilder connectionBuilder) where THub : Hub
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.Extensions.DependencyInjection\SignalRDependencyInjectionExtensions.cs
using Microsoft.AspNetCore.SignalR;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class SignalRDependencyInjectionExtensions
	{
		public static ISignalRServerBuilder AddSignalRCore(this IServiceCollection services)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Protocols.Json\Microsoft.AspNetCore.SignalR\JsonHubProtocolOptions.cs
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Microsoft.AspNetCore.SignalR
{
	public class JsonHubProtocolOptions
	{
		public JsonSerializerOptions PayloadSerializerOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.SignalR.Protocols.Json\Microsoft.AspNetCore.SignalR.Protocol\JsonHubProtocol.cs
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;
using System;
using System.Buffers;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public sealed class JsonHubProtocol : IHubProtocol
	{
		public string Name
		{
			get
			{
				throw null;
			}
		}

		public TransferFormat TransferFormat
		{
			get
			{
				throw null;
			}
		}

		public int Version
		{
			get
			{
				throw null;
			}
		}

		public JsonHubProtocol()
		{
		}

		public JsonHubProtocol(IOptions<JsonHubProtocolOptions> options)
		{
		}

		public ReadOnlyMemory<byte> GetMessageBytes(HubMessage message)
		{
			throw null;
		}

		public bool IsVersionSupported(int version)
		{
			throw null;
		}

		public bool TryParseMessage(ref ReadOnlySequence<byte> input, IInvocationBinder binder, out HubMessage message)
		{
			throw null;
		}

		public void WriteMessage(HubMessage message, IBufferWriter<byte> output)
		{
		}
	}
}


// Microsoft.AspNetCore.SignalR.Protocols.Json\Microsoft.Extensions.DependencyInjection\JsonProtocolDependencyInjectionExtensions.cs
using Microsoft.AspNetCore.SignalR;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class JsonProtocolDependencyInjectionExtensions
	{
		public static TBuilder AddJsonProtocol<TBuilder>(this TBuilder builder) where TBuilder : ISignalRBuilder
		{
			throw null;
		}

		public static TBuilder AddJsonProtocol<TBuilder>(this TBuilder builder, Action<JsonHubProtocolOptions> configure) where TBuilder : ISignalRBuilder
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\Base64UrlTextEncoder.cs
namespace Microsoft.AspNetCore.WebUtilities
{
	public static class Base64UrlTextEncoder
	{
		public static byte[] Decode(string text)
		{
			throw null;
		}

		public static string Encode(byte[] data)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\BufferedReadStream.cs
using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class BufferedReadStream : Stream
	{
		public ArraySegment<byte> BufferedData
		{
			get
			{
				throw null;
			}
		}

		public override bool CanRead
		{
			get
			{
				throw null;
			}
		}

		public override bool CanSeek
		{
			get
			{
				throw null;
			}
		}

		public override bool CanTimeout
		{
			get
			{
				throw null;
			}
		}

		public override bool CanWrite
		{
			get
			{
				throw null;
			}
		}

		public override long Length
		{
			get
			{
				throw null;
			}
		}

		public override long Position
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public BufferedReadStream(Stream inner, int bufferSize)
		{
		}

		public BufferedReadStream(Stream inner, int bufferSize, ArrayPool<byte> bytePool)
		{
		}

		protected override void Dispose(bool disposing)
		{
		}

		public bool EnsureBuffered()
		{
			throw null;
		}

		public bool EnsureBuffered(int minCount)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task<bool> EnsureBufferedAsync(int minCount, CancellationToken cancellationToken)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task<bool> EnsureBufferedAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public override void Flush()
		{
		}

		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public string ReadLine(int lengthLimit)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task<string> ReadLineAsync(int lengthLimit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw null;
		}

		public override void SetLength(long value)
		{
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
		}

		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\FileBufferingReadStream.cs
using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class FileBufferingReadStream : Stream
	{
		public override bool CanRead
		{
			get
			{
				throw null;
			}
		}

		public override bool CanSeek
		{
			get
			{
				throw null;
			}
		}

		public override bool CanWrite
		{
			get
			{
				throw null;
			}
		}

		public bool InMemory
		{
			get
			{
				throw null;
			}
		}

		public override long Length
		{
			get
			{
				throw null;
			}
		}

		public override long Position
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public string TempFileName
		{
			get
			{
				throw null;
			}
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold)
		{
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, Func<string> tempFileDirectoryAccessor)
		{
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, Func<string> tempFileDirectoryAccessor, ArrayPool<byte> bytePool)
		{
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, string tempFileDirectory)
		{
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, string tempFileDirectory, ArrayPool<byte> bytePool)
		{
		}

		protected override void Dispose(bool disposing)
		{
		}

		[DebuggerStepThrough]
		public override ValueTask DisposeAsync()
		{
			throw null;
		}

		public override void Flush()
		{
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw null;
		}

		public override void SetLength(long value)
		{
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
		}

		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\FileBufferingWriteStream.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public sealed class FileBufferingWriteStream : Stream
	{
		public override bool CanRead
		{
			get
			{
				throw null;
			}
		}

		public override bool CanSeek
		{
			get
			{
				throw null;
			}
		}

		public override bool CanWrite
		{
			get
			{
				throw null;
			}
		}

		public override long Length
		{
			get
			{
				throw null;
			}
		}

		public override long Position
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		internal bool Disposed
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal FileStream FileStream
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal PagedByteBuffer PagedByteBuffer
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FileBufferingWriteStream(int memoryThreshold = 32768, long? bufferLimit = null, Func<string> tempFileDirectoryAccessor = null)
		{
		}

		protected override void Dispose(bool disposing)
		{
		}

		[DebuggerStepThrough]
		public override ValueTask DisposeAsync()
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task DrainBufferAsync(Stream destination, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override void Flush()
		{
		}

		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw null;
		}

		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw null;
		}

		public override void SetLength(long value)
		{
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
		}

		[DebuggerStepThrough]
		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\FileMultipartSection.cs
using Microsoft.Net.Http.Headers;
using System.IO;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class FileMultipartSection
	{
		public string FileName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Stream FileStream
		{
			get
			{
				throw null;
			}
		}

		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MultipartSection Section
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FileMultipartSection(MultipartSection section)
		{
		}

		public FileMultipartSection(MultipartSection section, ContentDispositionHeaderValue header)
		{
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\FormMultipartSection.cs
using Microsoft.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class FormMultipartSection
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MultipartSection Section
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FormMultipartSection(MultipartSection section)
		{
		}

		public FormMultipartSection(MultipartSection section, ContentDispositionHeaderValue header)
		{
		}

		public Task<string> GetValueAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\FormPipeReader.cs
using Microsoft.Extensions.Primitives;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class FormPipeReader
	{
		public int KeyLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int ValueCountLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int ValueLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public FormPipeReader(PipeReader pipeReader)
		{
		}

		public FormPipeReader(PipeReader pipeReader, Encoding encoding)
		{
		}

		[DebuggerStepThrough]
		public Task<Dictionary<string, StringValues>> ReadFormAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		internal void ParseFormValues(ref ReadOnlySequence<byte> buffer, ref KeyValueAccumulator accumulator, bool isFinalBlock)
		{
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\FormReader.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class FormReader : IDisposable
	{
		public const int DefaultKeyLengthLimit = 2048;

		public const int DefaultValueCountLimit = 1024;

		public const int DefaultValueLengthLimit = 4194304;

		public int KeyLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int ValueCountLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int ValueLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public FormReader(Stream stream)
		{
		}

		public FormReader(Stream stream, Encoding encoding)
		{
		}

		public FormReader(Stream stream, Encoding encoding, ArrayPool<char> charPool)
		{
		}

		public FormReader(string data)
		{
		}

		public FormReader(string data, ArrayPool<char> charPool)
		{
		}

		public void Dispose()
		{
		}

		public Dictionary<string, StringValues> ReadForm()
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task<Dictionary<string, StringValues>> ReadFormAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public KeyValuePair<string, string>? ReadNextPair()
		{
			throw null;
		}

		[DebuggerStepThrough]
		public Task<KeyValuePair<string, string>?> ReadNextPairAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\HttpRequestStreamReader.cs
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class HttpRequestStreamReader : TextReader
	{
		public HttpRequestStreamReader(Stream stream, Encoding encoding)
		{
		}

		public HttpRequestStreamReader(Stream stream, Encoding encoding, int bufferSize)
		{
		}

		public HttpRequestStreamReader(Stream stream, Encoding encoding, int bufferSize, ArrayPool<byte> bytePool, ArrayPool<char> charPool)
		{
		}

		protected override void Dispose(bool disposing)
		{
		}

		public override int Peek()
		{
			throw null;
		}

		public override int Read()
		{
			throw null;
		}

		public override int Read(char[] buffer, int index, int count)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public override Task<int> ReadAsync(char[] buffer, int index, int count)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\HttpResponseStreamWriter.cs
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class HttpResponseStreamWriter : TextWriter
	{
		internal const int DefaultBufferSize = 16384;

		public override Encoding Encoding
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HttpResponseStreamWriter(Stream stream, Encoding encoding)
		{
		}

		public HttpResponseStreamWriter(Stream stream, Encoding encoding, int bufferSize)
		{
		}

		public HttpResponseStreamWriter(Stream stream, Encoding encoding, int bufferSize, ArrayPool<byte> bytePool, ArrayPool<char> charPool)
		{
		}

		protected override void Dispose(bool disposing)
		{
		}

		[DebuggerStepThrough]
		public override ValueTask DisposeAsync()
		{
			throw null;
		}

		public override void Flush()
		{
		}

		public override Task FlushAsync()
		{
			throw null;
		}

		public override void Write(char value)
		{
		}

		public override void Write(char[] values, int index, int count)
		{
		}

		public override void Write(string value)
		{
		}

		public override Task WriteAsync(char value)
		{
			throw null;
		}

		public override Task WriteAsync(char[] values, int index, int count)
		{
			throw null;
		}

		public override Task WriteAsync(string value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\KeyValueAccumulator.cs
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.WebUtilities
{
	public struct KeyValueAccumulator
	{
		private object _dummy;

		private int _dummyPrimitive;

		public bool HasValues
		{
			get
			{
				throw null;
			}
		}

		public int KeyCount
		{
			get
			{
				throw null;
			}
		}

		public int ValueCount
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public void Append(string key, string value)
		{
		}

		public Dictionary<string, StringValues> GetResults()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\MultipartReader.cs
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class MultipartReader
	{
		public const int DefaultHeadersCountLimit = 16;

		public const int DefaultHeadersLengthLimit = 16384;

		public long? BodyLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int HeadersCountLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public int HeadersLengthLimit
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public MultipartReader(string boundary, Stream stream)
		{
		}

		public MultipartReader(string boundary, Stream stream, int bufferSize)
		{
		}

		[DebuggerStepThrough]
		public Task<MultipartSection> ReadNextSectionAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\MultipartSection.cs
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class MultipartSection
	{
		public long? BaseStreamOffset
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public Stream Body
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ContentDisposition
		{
			get
			{
				throw null;
			}
		}

		public string ContentType
		{
			get
			{
				throw null;
			}
		}

		public Dictionary<string, StringValues> Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\MultipartSectionConverterExtensions.cs
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class MultipartSectionConverterExtensions
	{
		public static FileMultipartSection AsFileSection(this MultipartSection section)
		{
			throw null;
		}

		public static FormMultipartSection AsFormDataSection(this MultipartSection section)
		{
			throw null;
		}

		public static ContentDispositionHeaderValue GetContentDispositionHeader(this MultipartSection section)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\MultipartSectionStreamExtensions.cs
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class MultipartSectionStreamExtensions
	{
		[DebuggerStepThrough]
		public static Task<string> ReadAsStringAsync(this MultipartSection section)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\QueryHelpers.cs
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class QueryHelpers
	{
		public static string AddQueryString(string uri, IDictionary<string, string> queryString)
		{
			throw null;
		}

		public static string AddQueryString(string uri, string name, string value)
		{
			throw null;
		}

		public static Dictionary<string, StringValues> ParseNullableQuery(string queryString)
		{
			throw null;
		}

		public static Dictionary<string, StringValues> ParseQuery(string queryString)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\ReasonPhrases.cs
namespace Microsoft.AspNetCore.WebUtilities
{
	public static class ReasonPhrases
	{
		public static string GetReasonPhrase(int statusCode)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\StreamHelperExtensions.cs
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class StreamHelperExtensions
	{
		[DebuggerStepThrough]
		public static Task DrainAsync(this Stream stream, ArrayPool<byte> bytePool, long? limit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public static Task DrainAsync(this Stream stream, long? limit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public static Task DrainAsync(this Stream stream, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\WebEncoders.cs
using System;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class WebEncoders
	{
		public static byte[] Base64UrlDecode(string input)
		{
			throw null;
		}

		public static byte[] Base64UrlDecode(string input, int offset, char[] buffer, int bufferOffset, int count)
		{
			throw null;
		}

		public static byte[] Base64UrlDecode(string input, int offset, int count)
		{
			throw null;
		}

		public static string Base64UrlEncode(byte[] input)
		{
			throw null;
		}

		public static int Base64UrlEncode(byte[] input, int offset, char[] output, int outputOffset, int count)
		{
			throw null;
		}

		public static string Base64UrlEncode(byte[] input, int offset, int count)
		{
			throw null;
		}

		public static string Base64UrlEncode(ReadOnlySpan<byte> input)
		{
			throw null;
		}

		public static int GetArraySizeRequiredToDecode(int count)
		{
			throw null;
		}

		public static int GetArraySizeRequiredToEncode(int count)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting\ConsoleLifetimeOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Hosting
{
	public class ConsoleLifetimeOptions
	{
		public bool SuppressStatusMessages
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting\Host.cs
namespace Microsoft.Extensions.Hosting
{
	public static class Host
	{
		public static IHostBuilder CreateDefaultBuilder()
		{
			throw null;
		}

		public static IHostBuilder CreateDefaultBuilder(string[] args)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting\HostBuilder.cs
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Hosting
{
	public class HostBuilder : IHostBuilder
	{
		public IDictionary<object, object> Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IHost Build()
		{
			throw null;
		}

		public IHostBuilder ConfigureAppConfiguration(Action<HostBuilderContext, IConfigurationBuilder> configureDelegate)
		{
			throw null;
		}

		public IHostBuilder ConfigureContainer<TContainerBuilder>(Action<HostBuilderContext, TContainerBuilder> configureDelegate)
		{
			throw null;
		}

		public IHostBuilder ConfigureHostConfiguration(Action<IConfigurationBuilder> configureDelegate)
		{
			throw null;
		}

		public IHostBuilder ConfigureServices(Action<HostBuilderContext, IServiceCollection> configureDelegate)
		{
			throw null;
		}

		public IHostBuilder UseServiceProviderFactory<TContainerBuilder>(IServiceProviderFactory<TContainerBuilder> factory)
		{
			throw null;
		}

		public IHostBuilder UseServiceProviderFactory<TContainerBuilder>(Func<HostBuilderContext, IServiceProviderFactory<TContainerBuilder>> factory)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting\HostingHostBuilderExtensions.cs
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public static class HostingHostBuilderExtensions
	{
		public static IHostBuilder ConfigureAppConfiguration(this IHostBuilder hostBuilder, Action<IConfigurationBuilder> configureDelegate)
		{
			throw null;
		}

		public static IHostBuilder ConfigureContainer<TContainerBuilder>(this IHostBuilder hostBuilder, Action<TContainerBuilder> configureDelegate)
		{
			throw null;
		}

		public static IHostBuilder ConfigureLogging(this IHostBuilder hostBuilder, Action<HostBuilderContext, ILoggingBuilder> configureLogging)
		{
			throw null;
		}

		public static IHostBuilder ConfigureLogging(this IHostBuilder hostBuilder, Action<ILoggingBuilder> configureLogging)
		{
			throw null;
		}

		public static IHostBuilder ConfigureServices(this IHostBuilder hostBuilder, Action<IServiceCollection> configureDelegate)
		{
			throw null;
		}

		public static Task RunConsoleAsync(this IHostBuilder hostBuilder, Action<ConsoleLifetimeOptions> configureOptions, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task RunConsoleAsync(this IHostBuilder hostBuilder, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static IHostBuilder UseConsoleLifetime(this IHostBuilder hostBuilder)
		{
			throw null;
		}

		public static IHostBuilder UseConsoleLifetime(this IHostBuilder hostBuilder, Action<ConsoleLifetimeOptions> configureOptions)
		{
			throw null;
		}

		public static IHostBuilder UseContentRoot(this IHostBuilder hostBuilder, string contentRoot)
		{
			throw null;
		}

		public static IHostBuilder UseDefaultServiceProvider(this IHostBuilder hostBuilder, Action<ServiceProviderOptions> configure)
		{
			throw null;
		}

		public static IHostBuilder UseDefaultServiceProvider(this IHostBuilder hostBuilder, Action<HostBuilderContext, ServiceProviderOptions> configure)
		{
			throw null;
		}

		public static IHostBuilder UseEnvironment(this IHostBuilder hostBuilder, string environment)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting\HostOptions.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Hosting
{
	public class HostOptions
	{
		public TimeSpan ShutdownTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting.Internal\ApplicationLifetime.cs
using Microsoft.Extensions.Logging;
using System.Threading;

namespace Microsoft.Extensions.Hosting.Internal
{
	public class ApplicationLifetime : IApplicationLifetime, IHostApplicationLifetime
	{
		public CancellationToken ApplicationStarted
		{
			get
			{
				throw null;
			}
		}

		public CancellationToken ApplicationStopped
		{
			get
			{
				throw null;
			}
		}

		public CancellationToken ApplicationStopping
		{
			get
			{
				throw null;
			}
		}

		public ApplicationLifetime(ILogger<ApplicationLifetime> logger)
		{
		}

		public void NotifyStarted()
		{
		}

		public void NotifyStopped()
		{
		}

		public void StopApplication()
		{
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting.Internal\ConsoleLifetime.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting.Internal
{
	public class ConsoleLifetime : IHostLifetime, IDisposable
	{
		public ConsoleLifetime(IOptions<ConsoleLifetimeOptions> options, IHostEnvironment environment, IHostApplicationLifetime applicationLifetime, IOptions<HostOptions> hostOptions)
		{
		}

		public ConsoleLifetime(IOptions<ConsoleLifetimeOptions> options, IHostEnvironment environment, IHostApplicationLifetime applicationLifetime, IOptions<HostOptions> hostOptions, ILoggerFactory loggerFactory)
		{
		}

		public void Dispose()
		{
		}

		public Task StopAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public Task WaitForStartAsync(CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting.Internal\HostingEnvironment.cs
using Microsoft.Extensions.FileProviders;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Hosting.Internal
{
	public class HostingEnvironment : IHostEnvironment, IHostingEnvironment
	{
		public string ApplicationName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IFileProvider ContentRootFileProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string ContentRootPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public string EnvironmentName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.DependencyInjection\ServiceCollectionHostedServiceExtensions.cs
using Microsoft.Extensions.Hosting;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class ServiceCollectionHostedServiceExtensions
	{
		public static IServiceCollection AddHostedService<THostedService>(this IServiceCollection services) where THostedService : class, IHostedService
		{
			throw null;
		}

		public static IServiceCollection AddHostedService<THostedService>(this IServiceCollection services, Func<IServiceProvider, THostedService> implementationFactory) where THostedService : class, IHostedService
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\BackgroundService.cs
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public abstract class BackgroundService : IHostedService, IDisposable
	{
		public virtual void Dispose()
		{
		}

		protected abstract Task ExecuteAsync(CancellationToken stoppingToken);

		public virtual Task StartAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public virtual Task StopAsync(CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\EnvironmentName.cs
using System;

namespace Microsoft.Extensions.Hosting
{
	[Obsolete("This type is obsolete and will be removed in a future version. The recommended alternative is Microsoft.Extensions.Hosting.Environments.", false)]
	public static class EnvironmentName
	{
		public static readonly string Development;

		public static readonly string Production;

		public static readonly string Staging;
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\Environments.cs
namespace Microsoft.Extensions.Hosting
{
	public static class Environments
	{
		public static readonly string Development;

		public static readonly string Production;

		public static readonly string Staging;
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\HostBuilderContext.cs
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Hosting
{
	public class HostBuilderContext
	{
		public IConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IHostEnvironment HostingEnvironment
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public IDictionary<object, object> Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HostBuilderContext(IDictionary<object, object> properties)
		{
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\HostDefaults.cs
namespace Microsoft.Extensions.Hosting
{
	public static class HostDefaults
	{
		public static readonly string ApplicationKey;

		public static readonly string ContentRootKey;

		public static readonly string EnvironmentKey;
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\HostEnvironmentEnvExtensions.cs
namespace Microsoft.Extensions.Hosting
{
	public static class HostEnvironmentEnvExtensions
	{
		public static bool IsDevelopment(this IHostEnvironment hostEnvironment)
		{
			throw null;
		}

		public static bool IsEnvironment(this IHostEnvironment hostEnvironment, string environmentName)
		{
			throw null;
		}

		public static bool IsProduction(this IHostEnvironment hostEnvironment)
		{
			throw null;
		}

		public static bool IsStaging(this IHostEnvironment hostEnvironment)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\HostingAbstractionsHostBuilderExtensions.cs
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public static class HostingAbstractionsHostBuilderExtensions
	{
		public static IHost Start(this IHostBuilder hostBuilder)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public static Task<IHost> StartAsync(this IHostBuilder hostBuilder, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\HostingAbstractionsHostExtensions.cs
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public static class HostingAbstractionsHostExtensions
	{
		public static void Run(this IHost host)
		{
		}

		[DebuggerStepThrough]
		public static Task RunAsync(this IHost host, CancellationToken token = default(CancellationToken))
		{
			throw null;
		}

		public static void Start(this IHost host)
		{
		}

		public static Task StopAsync(this IHost host, TimeSpan timeout)
		{
			throw null;
		}

		public static void WaitForShutdown(this IHost host)
		{
		}

		[DebuggerStepThrough]
		public static Task WaitForShutdownAsync(this IHost host, CancellationToken token = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\HostingEnvironmentExtensions.cs
namespace Microsoft.Extensions.Hosting
{
	public static class HostingEnvironmentExtensions
	{
		public static bool IsDevelopment(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}

		public static bool IsEnvironment(this IHostingEnvironment hostingEnvironment, string environmentName)
		{
			throw null;
		}

		public static bool IsProduction(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}

		public static bool IsStaging(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IApplicationLifetime.cs
using System;
using System.Threading;

namespace Microsoft.Extensions.Hosting
{
	[Obsolete("This type is obsolete and will be removed in a future version. The recommended alternative is Microsoft.Extensions.Hosting.IHostApplicationLifetime.", false)]
	public interface IApplicationLifetime
	{
		CancellationToken ApplicationStarted
		{
			get;
		}

		CancellationToken ApplicationStopped
		{
			get;
		}

		CancellationToken ApplicationStopping
		{
			get;
		}

		void StopApplication();
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IHost.cs
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public interface IHost : IDisposable
	{
		IServiceProvider Services
		{
			get;
		}

		Task StartAsync(CancellationToken cancellationToken = default(CancellationToken));

		Task StopAsync(CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IHostApplicationLifetime.cs
using System.Threading;

namespace Microsoft.Extensions.Hosting
{
	public interface IHostApplicationLifetime
	{
		CancellationToken ApplicationStarted
		{
			get;
		}

		CancellationToken ApplicationStopped
		{
			get;
		}

		CancellationToken ApplicationStopping
		{
			get;
		}

		void StopApplication();
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IHostBuilder.cs
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;

namespace Microsoft.Extensions.Hosting
{
	public interface IHostBuilder
	{
		IDictionary<object, object> Properties
		{
			get;
		}

		IHost Build();

		IHostBuilder ConfigureAppConfiguration(Action<HostBuilderContext, IConfigurationBuilder> configureDelegate);

		IHostBuilder ConfigureContainer<TContainerBuilder>(Action<HostBuilderContext, TContainerBuilder> configureDelegate);

		IHostBuilder ConfigureHostConfiguration(Action<IConfigurationBuilder> configureDelegate);

		IHostBuilder ConfigureServices(Action<HostBuilderContext, IServiceCollection> configureDelegate);

		IHostBuilder UseServiceProviderFactory<TContainerBuilder>(IServiceProviderFactory<TContainerBuilder> factory);

		IHostBuilder UseServiceProviderFactory<TContainerBuilder>(Func<HostBuilderContext, IServiceProviderFactory<TContainerBuilder>> factory);
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IHostedService.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public interface IHostedService
	{
		Task StartAsync(CancellationToken cancellationToken);

		Task StopAsync(CancellationToken cancellationToken);
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IHostEnvironment.cs
using Microsoft.Extensions.FileProviders;

namespace Microsoft.Extensions.Hosting
{
	public interface IHostEnvironment
	{
		string ApplicationName
		{
			get;
			set;
		}

		IFileProvider ContentRootFileProvider
		{
			get;
			set;
		}

		string ContentRootPath
		{
			get;
			set;
		}

		string EnvironmentName
		{
			get;
			set;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IHostingEnvironment.cs
using Microsoft.Extensions.FileProviders;
using System;

namespace Microsoft.Extensions.Hosting
{
	[Obsolete("This type is obsolete and will be removed in a future version. The recommended alternative is Microsoft.Extensions.Hosting.IHostEnvironment.", false)]
	public interface IHostingEnvironment
	{
		string ApplicationName
		{
			get;
			set;
		}

		IFileProvider ContentRootFileProvider
		{
			get;
			set;
		}

		string ContentRootPath
		{
			get;
			set;
		}

		string EnvironmentName
		{
			get;
			set;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\IHostLifetime.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public interface IHostLifetime
	{
		Task StopAsync(CancellationToken cancellationToken);

		Task WaitForStartAsync(CancellationToken cancellationToken);
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.DependencyInjection\HttpClientBuilderExtensions.cs
using Microsoft.Extensions.Http;
using System;
using System.Net.Http;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class HttpClientBuilderExtensions
	{
		public static IHttpClientBuilder AddHttpMessageHandler(this IHttpClientBuilder builder, Func<IServiceProvider, DelegatingHandler> configureHandler)
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpMessageHandler(this IHttpClientBuilder builder, Func<DelegatingHandler> configureHandler)
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpMessageHandler<THandler>(this IHttpClientBuilder builder) where THandler : DelegatingHandler
		{
			throw null;
		}

		public static IHttpClientBuilder AddTypedClient<TClient>(this IHttpClientBuilder builder) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddTypedClient<TClient>(this IHttpClientBuilder builder, Func<HttpClient, IServiceProvider, TClient> factory) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddTypedClient<TClient>(this IHttpClientBuilder builder, Func<HttpClient, TClient> factory) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddTypedClient<TClient, TImplementation>(this IHttpClientBuilder builder) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder ConfigureHttpClient(this IHttpClientBuilder builder, Action<IServiceProvider, HttpClient> configureClient)
		{
			throw null;
		}

		public static IHttpClientBuilder ConfigureHttpClient(this IHttpClientBuilder builder, Action<HttpClient> configureClient)
		{
			throw null;
		}

		public static IHttpClientBuilder ConfigureHttpMessageHandlerBuilder(this IHttpClientBuilder builder, Action<HttpMessageHandlerBuilder> configureBuilder)
		{
			throw null;
		}

		public static IHttpClientBuilder ConfigurePrimaryHttpMessageHandler(this IHttpClientBuilder builder, Func<IServiceProvider, HttpMessageHandler> configureHandler)
		{
			throw null;
		}

		public static IHttpClientBuilder ConfigurePrimaryHttpMessageHandler(this IHttpClientBuilder builder, Func<HttpMessageHandler> configureHandler)
		{
			throw null;
		}

		public static IHttpClientBuilder ConfigurePrimaryHttpMessageHandler<THandler>(this IHttpClientBuilder builder) where THandler : HttpMessageHandler
		{
			throw null;
		}

		public static IHttpClientBuilder SetHandlerLifetime(this IHttpClientBuilder builder, TimeSpan handlerLifetime)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.DependencyInjection\HttpClientFactoryServiceCollectionExtensions.cs
using System;
using System.Net.Http;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class HttpClientFactoryServiceCollectionExtensions
	{
		public static IServiceCollection AddHttpClient(this IServiceCollection services)
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient(this IServiceCollection services, string name)
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient(this IServiceCollection services, string name, Action<IServiceProvider, HttpClient> configureClient)
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient(this IServiceCollection services, string name, Action<HttpClient> configureClient)
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient>(this IServiceCollection services) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient>(this IServiceCollection services, Action<IServiceProvider, HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient>(this IServiceCollection services, Action<HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient>(this IServiceCollection services, string name) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient>(this IServiceCollection services, string name, Action<IServiceProvider, HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient>(this IServiceCollection services, string name, Action<HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, Action<IServiceProvider, HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, Action<HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, string name) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, string name, Action<IServiceProvider, HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, string name, Action<HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.DependencyInjection\IHttpClientBuilder.cs
namespace Microsoft.Extensions.DependencyInjection
{
	public interface IHttpClientBuilder
	{
		string Name
		{
			get;
		}

		IServiceCollection Services
		{
			get;
		}
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.Http\HttpClientFactoryOptions.cs
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Http
{
	public class HttpClientFactoryOptions
	{
		public TimeSpan HandlerLifetime
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IList<Action<HttpClient>> HttpClientActions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<Action<HttpMessageHandlerBuilder>> HttpMessageHandlerBuilderActions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool SuppressHandlerScope
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.Http\HttpMessageHandlerBuilder.cs
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Http
{
	public abstract class HttpMessageHandlerBuilder
	{
		public abstract IList<DelegatingHandler> AdditionalHandlers
		{
			get;
		}

		public abstract string Name
		{
			get;
			set;
		}

		public abstract HttpMessageHandler PrimaryHandler
		{
			get;
			set;
		}

		public virtual IServiceProvider Services
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public abstract HttpMessageHandler Build();

		protected internal static HttpMessageHandler CreateHandlerPipeline(HttpMessageHandler primaryHandler, IEnumerable<DelegatingHandler> additionalHandlers)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.Http\IHttpMessageHandlerBuilderFilter.cs
using System;

namespace Microsoft.Extensions.Http
{
	public interface IHttpMessageHandlerBuilderFilter
	{
		Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next);
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.Http\ITypedHttpClientFactory.cs
using System.Net.Http;

namespace Microsoft.Extensions.Http
{
	public interface ITypedHttpClientFactory<TClient>
	{
		TClient CreateClient(HttpClient httpClient);
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.Http.Logging\LoggingHttpMessageHandler.cs
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Http.Logging
{
	public class LoggingHttpMessageHandler : DelegatingHandler
	{
		public LoggingHttpMessageHandler(ILogger logger)
		{
		}

		[DebuggerStepThrough]
		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.Http.Logging\LoggingScopeHttpMessageHandler.cs
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Http.Logging
{
	public class LoggingScopeHttpMessageHandler : DelegatingHandler
	{
		public LoggingScopeHttpMessageHandler(ILogger logger)
		{
		}

		[DebuggerStepThrough]
		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\System.Net.Http\HttpClientFactoryExtensions.cs
namespace System.Net.Http
{
	public static class HttpClientFactoryExtensions
	{
		public static HttpClient CreateClient(this IHttpClientFactory factory)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\System.Net.Http\HttpMessageHandlerFactoryExtensions.cs
namespace System.Net.Http
{
	public static class HttpMessageHandlerFactoryExtensions
	{
		public static HttpMessageHandler CreateHandler(this IHttpMessageHandlerFactory factory)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\System.Net.Http\IHttpClientFactory.cs
namespace System.Net.Http
{
	public interface IHttpClientFactory
	{
		HttpClient CreateClient(string name);
	}
}


// Microsoft.Extensions.Http\System.Net.Http\IHttpMessageHandlerFactory.cs
namespace System.Net.Http
{
	public interface IHttpMessageHandlerFactory
	{
		HttpMessageHandler CreateHandler(string name);
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.DependencyInjection\LocalizationServiceCollectionExtensions.cs
using Microsoft.Extensions.Localization;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class LocalizationServiceCollectionExtensions
	{
		public static IServiceCollection AddLocalization(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddLocalization(this IServiceCollection services, Action<LocalizationOptions> setupAction)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\IResourceNamesCache.cs
using System;
using System.Collections.Generic;

namespace Microsoft.Extensions.Localization
{
	public interface IResourceNamesCache
	{
		IList<string> GetOrAdd(string name, Func<string, IList<string>> valueFactory);
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\LocalizationOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Localization
{
	public class LocalizationOptions
	{
		public string ResourcesPath
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		public LocalizationOptions()
		{
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\ResourceLocationAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Localization
{
	[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false, Inherited = false)]
	public class ResourceLocationAttribute : Attribute
	{
		public string ResourceLocation
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ResourceLocationAttribute(string resourceLocation)
		{
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\ResourceManagerStringLocalizer.cs
using Microsoft.Extensions.Localization.Internal;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Resources;

namespace Microsoft.Extensions.Localization
{
	public class ResourceManagerStringLocalizer : IStringLocalizer
	{
		public virtual LocalizedString this[string name]
		{
			get
			{
				throw null;
			}
		}

		public virtual LocalizedString this[string name, params object[] arguments]
		{
			get
			{
				throw null;
			}
		}

		public ResourceManagerStringLocalizer(ResourceManager resourceManager, AssemblyWrapper resourceAssemblyWrapper, string baseName, IResourceNamesCache resourceNamesCache, ILogger logger)
		{
		}

		public ResourceManagerStringLocalizer(ResourceManager resourceManager, IResourceStringProvider resourceStringProvider, string baseName, IResourceNamesCache resourceNamesCache, ILogger logger)
		{
		}

		public ResourceManagerStringLocalizer(ResourceManager resourceManager, Assembly resourceAssembly, string baseName, IResourceNamesCache resourceNamesCache, ILogger logger)
		{
		}

		public virtual IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures)
		{
			throw null;
		}

		protected IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures, CultureInfo culture)
		{
			throw null;
		}

		protected string GetStringSafely(string name, CultureInfo culture)
		{
			throw null;
		}

		[Obsolete("This method is obsolete. Use `CurrentCulture` and `CurrentUICulture` instead.")]
		public IStringLocalizer WithCulture(CultureInfo culture)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\ResourceManagerStringLocalizerFactory.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Reflection;

namespace Microsoft.Extensions.Localization
{
	public class ResourceManagerStringLocalizerFactory : IStringLocalizerFactory
	{
		public ResourceManagerStringLocalizerFactory(IOptions<LocalizationOptions> localizationOptions, ILoggerFactory loggerFactory)
		{
		}

		public IStringLocalizer Create(string baseName, string location)
		{
			throw null;
		}

		public IStringLocalizer Create(Type resourceSource)
		{
			throw null;
		}

		protected virtual ResourceManagerStringLocalizer CreateResourceManagerStringLocalizer(Assembly assembly, string baseName)
		{
			throw null;
		}

		protected virtual ResourceLocationAttribute GetResourceLocationAttribute(Assembly assembly)
		{
			throw null;
		}

		protected virtual string GetResourcePrefix(TypeInfo typeInfo)
		{
			throw null;
		}

		protected virtual string GetResourcePrefix(TypeInfo typeInfo, string baseNamespace, string resourcesRelativePath)
		{
			throw null;
		}

		protected virtual string GetResourcePrefix(string baseResourceName, string baseNamespace)
		{
			throw null;
		}

		protected virtual string GetResourcePrefix(string location, string baseName, string resourceLocation)
		{
			throw null;
		}

		protected virtual RootNamespaceAttribute GetRootNamespaceAttribute(Assembly assembly)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\ResourceManagerWithCultureStringLocalizer.cs
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Resources;

namespace Microsoft.Extensions.Localization
{
	[Obsolete("This method is obsolete. Use `CurrentCulture` and `CurrentUICulture` instead.")]
	public class ResourceManagerWithCultureStringLocalizer : ResourceManagerStringLocalizer
	{
		public override LocalizedString this[string name]
		{
			get
			{
				throw null;
			}
		}

		public override LocalizedString this[string name, params object[] arguments]
		{
			get
			{
				throw null;
			}
		}

		public ResourceManagerWithCultureStringLocalizer(ResourceManager resourceManager, Assembly resourceAssembly, string baseName, IResourceNamesCache resourceNamesCache, CultureInfo culture, ILogger logger)
			: base((ResourceManager)null, (Assembly)null, (string)null, (IResourceNamesCache)null, (ILogger)null)
		{
		}

		public override IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\ResourceNamesCache.cs
using System;
using System.Collections.Generic;

namespace Microsoft.Extensions.Localization
{
	public class ResourceNamesCache : IResourceNamesCache
	{
		public ResourceNamesCache()
		{
		}

		public IList<string> GetOrAdd(string name, Func<string, IList<string>> valueFactory)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\RootNamespaceAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Localization
{
	[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false, Inherited = false)]
	public class RootNamespaceAttribute : Attribute
	{
		public string RootNamespace
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RootNamespaceAttribute(string rootNamespace)
		{
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization.Internal\AssemblyWrapper.cs
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Localization.Internal
{
	public class AssemblyWrapper
	{
		public Assembly Assembly
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public virtual string FullName
		{
			get
			{
				throw null;
			}
		}

		public AssemblyWrapper(Assembly assembly)
		{
		}

		public virtual Stream GetManifestResourceStream(string name)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization.Internal\IResourceStringProvider.cs
using System.Collections.Generic;
using System.Globalization;

namespace Microsoft.Extensions.Localization.Internal
{
	public interface IResourceStringProvider
	{
		IList<string> GetAllResourceStrings(CultureInfo culture, bool throwOnMissing);
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization.Internal\ResourceManagerStringProvider.cs
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Resources;

namespace Microsoft.Extensions.Localization.Internal
{
	public class ResourceManagerStringProvider : IResourceStringProvider
	{
		public ResourceManagerStringProvider(IResourceNamesCache resourceCache, ResourceManager resourceManager, Assembly assembly, string baseName)
		{
		}

		public IList<string> GetAllResourceStrings(CultureInfo culture, bool throwOnMissing)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization.Abstractions\Microsoft.Extensions.Localization\IStringLocalizer.cs
using System;
using System.Collections.Generic;
using System.Globalization;

namespace Microsoft.Extensions.Localization
{
	public interface IStringLocalizer
	{
		LocalizedString this[string name]
		{
			get;
		}

		LocalizedString this[string name, params object[] arguments]
		{
			get;
		}

		IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures);

		[Obsolete("This method is obsolete. Use `CurrentCulture` and `CurrentUICulture` instead.")]
		IStringLocalizer WithCulture(CultureInfo culture);
	}
	public interface IStringLocalizer<out T> : IStringLocalizer
	{
	}
}


// Microsoft.Extensions.Localization.Abstractions\Microsoft.Extensions.Localization\IStringLocalizerFactory.cs
using System;

namespace Microsoft.Extensions.Localization
{
	public interface IStringLocalizerFactory
	{
		IStringLocalizer Create(string baseName, string location);

		IStringLocalizer Create(Type resourceSource);
	}
}


// Microsoft.Extensions.Localization.Abstractions\Microsoft.Extensions.Localization\LocalizedString.cs
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Localization
{
	public class LocalizedString
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool ResourceNotFound
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string SearchedLocation
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LocalizedString(string name, string value)
		{
		}

		public LocalizedString(string name, string value, bool resourceNotFound)
		{
		}

		public LocalizedString(string name, string value, bool resourceNotFound, string searchedLocation)
		{
		}

		public static implicit operator string(LocalizedString localizedString)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization.Abstractions\Microsoft.Extensions.Localization\StringLocalizer.cs
using System;
using System.Collections.Generic;
using System.Globalization;

namespace Microsoft.Extensions.Localization
{
	public class StringLocalizer<TResourceSource> : IStringLocalizer, IStringLocalizer<TResourceSource>
	{
		public virtual LocalizedString this[string name]
		{
			get
			{
				throw null;
			}
		}

		public virtual LocalizedString this[string name, params object[] arguments]
		{
			get
			{
				throw null;
			}
		}

		public StringLocalizer(IStringLocalizerFactory factory)
		{
		}

		public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures)
		{
			throw null;
		}

		[Obsolete("This method is obsolete. Use `CurrentCulture` and `CurrentUICulture` instead.")]
		public virtual IStringLocalizer WithCulture(CultureInfo culture)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization.Abstractions\Microsoft.Extensions.Localization\StringLocalizerExtensions.cs
using System.Collections.Generic;

namespace Microsoft.Extensions.Localization
{
	public static class StringLocalizerExtensions
	{
		public static IEnumerable<LocalizedString> GetAllStrings(this IStringLocalizer stringLocalizer)
		{
			throw null;
		}

		public static LocalizedString GetString(this IStringLocalizer stringLocalizer, string name)
		{
			throw null;
		}

		public static LocalizedString GetString(this IStringLocalizer stringLocalizer, string name, params object[] arguments)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.WebEncoders\Microsoft.Extensions.DependencyInjection\EncoderServiceCollectionExtensions.cs
using Microsoft.Extensions.WebEncoders;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class EncoderServiceCollectionExtensions
	{
		public static IServiceCollection AddWebEncoders(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddWebEncoders(this IServiceCollection services, Action<WebEncoderOptions> setupAction)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.WebEncoders\Microsoft.Extensions.WebEncoders\WebEncoderOptions.cs
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;

namespace Microsoft.Extensions.WebEncoders
{
	public sealed class WebEncoderOptions
	{
		public TextEncoderSettings TextEncoderSettings
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}
	}
}


// Microsoft.Extensions.WebEncoders\Microsoft.Extensions.WebEncoders.Testing\HtmlTestEncoder.cs
using System.IO;
using System.Text.Encodings.Web;

namespace Microsoft.Extensions.WebEncoders.Testing
{
	public sealed class HtmlTestEncoder : HtmlEncoder
	{
		public override int MaxOutputCharactersPerInputCharacter
		{
			get
			{
				throw null;
			}
		}

		public override void Encode(TextWriter output, char[] value, int startIndex, int characterCount)
		{
		}

		public override void Encode(TextWriter output, string value, int startIndex, int characterCount)
		{
		}

		public override string Encode(string value)
		{
			throw null;
		}

		public unsafe override int FindFirstCharacterToEncode(char* text, int textLength)
		{
			throw null;
		}

		public unsafe override bool TryEncodeUnicodeScalar(int unicodeScalar, char* buffer, int bufferLength, out int numberOfCharactersWritten)
		{
			throw null;
		}

		public override bool WillEncode(int unicodeScalar)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.WebEncoders\Microsoft.Extensions.WebEncoders.Testing\JavaScriptTestEncoder.cs
using System.IO;
using System.Text.Encodings.Web;

namespace Microsoft.Extensions.WebEncoders.Testing
{
	public class JavaScriptTestEncoder : JavaScriptEncoder
	{
		public override int MaxOutputCharactersPerInputCharacter
		{
			get
			{
				throw null;
			}
		}

		public override void Encode(TextWriter output, char[] value, int startIndex, int characterCount)
		{
		}

		public override void Encode(TextWriter output, string value, int startIndex, int characterCount)
		{
		}

		public override string Encode(string value)
		{
			throw null;
		}

		public unsafe override int FindFirstCharacterToEncode(char* text, int textLength)
		{
			throw null;
		}

		public unsafe override bool TryEncodeUnicodeScalar(int unicodeScalar, char* buffer, int bufferLength, out int numberOfCharactersWritten)
		{
			throw null;
		}

		public override bool WillEncode(int unicodeScalar)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.WebEncoders\Microsoft.Extensions.WebEncoders.Testing\UrlTestEncoder.cs
using System.IO;
using System.Text.Encodings.Web;

namespace Microsoft.Extensions.WebEncoders.Testing
{
	public class UrlTestEncoder : UrlEncoder
	{
		public override int MaxOutputCharactersPerInputCharacter
		{
			get
			{
				throw null;
			}
		}

		public override void Encode(TextWriter output, char[] value, int startIndex, int characterCount)
		{
		}

		public override void Encode(TextWriter output, string value, int startIndex, int characterCount)
		{
		}

		public override string Encode(string value)
		{
			throw null;
		}

		public unsafe override int FindFirstCharacterToEncode(char* text, int textLength)
		{
			throw null;
		}

		public unsafe override bool TryEncodeUnicodeScalar(int unicodeScalar, char* buffer, int bufferLength, out int numberOfCharactersWritten)
		{
			throw null;
		}

		public override bool WillEncode(int unicodeScalar)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\DotNetObjectReference.cs
using System;

namespace Microsoft.JSInterop
{
	public static class DotNetObjectReference
	{
		public static DotNetObjectReference<TValue> Create<TValue>(TValue value) where TValue : class
		{
			throw null;
		}
	}
	public sealed class DotNetObjectReference<TValue> : IDisposable where TValue : class
	{
		public TValue Value
		{
			get
			{
				throw null;
			}
		}

		internal DotNetObjectReference()
		{
		}

		public void Dispose()
		{
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\IJSInProcessRuntime.cs
namespace Microsoft.JSInterop
{
	public interface IJSInProcessRuntime : IJSRuntime
	{
		T Invoke<T>(string identifier, params object[] args);
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\IJSRuntime.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.JSInterop
{
	public interface IJSRuntime
	{
		ValueTask<TValue> InvokeAsync<TValue>(string identifier, object[] args);

		ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object[] args);
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSException.cs
using System;

namespace Microsoft.JSInterop
{
	public class JSException : Exception
	{
		public JSException(string message)
		{
		}

		public JSException(string message, Exception innerException)
		{
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSInProcessRuntime.cs
namespace Microsoft.JSInterop
{
	public abstract class JSInProcessRuntime : JSRuntime, IJSInProcessRuntime, IJSRuntime
	{
		protected abstract string InvokeJS(string identifier, string argsJson);

		public TValue Invoke<TValue>(string identifier, params object[] args)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSInProcessRuntimeExtensions.cs
namespace Microsoft.JSInterop
{
	public static class JSInProcessRuntimeExtensions
	{
		public static void InvokeVoid(this IJSInProcessRuntime jsRuntime, string identifier, params object[] args)
		{
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSInvokableAttribute.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.JSInterop
{
	[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
	public sealed class JSInvokableAttribute : Attribute
	{
		public string Identifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public JSInvokableAttribute()
		{
		}

		public JSInvokableAttribute(string identifier)
		{
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSRuntime.cs
using Microsoft.JSInterop.Infrastructure;
using System;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.JSInterop
{
	public abstract class JSRuntime : IJSRuntime
	{
		protected TimeSpan? DefaultAsyncTimeout
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
			}
		}

		protected internal JsonSerializerOptions JsonSerializerOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected JSRuntime()
		{
		}

		protected abstract void BeginInvokeJS(long taskId, string identifier, string argsJson);

		protected internal abstract void EndInvokeDotNet(DotNetInvocationInfo invocationInfo, in DotNetInvocationResult invocationResult);

		public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object[] args)
		{
			throw null;
		}

		public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object[] args)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSRuntimeExtensions.cs
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.JSInterop
{
	public static class JSRuntimeExtensions
	{
		public static ValueTask<TValue> InvokeAsync<TValue>(this IJSRuntime jsRuntime, string identifier, params object[] args)
		{
			throw null;
		}

		public static ValueTask<TValue> InvokeAsync<TValue>(this IJSRuntime jsRuntime, string identifier, CancellationToken cancellationToken, params object[] args)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public static ValueTask<TValue> InvokeAsync<TValue>(this IJSRuntime jsRuntime, string identifier, TimeSpan timeout, params object[] args)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public static ValueTask InvokeVoidAsync(this IJSRuntime jsRuntime, string identifier, params object[] args)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public static ValueTask InvokeVoidAsync(this IJSRuntime jsRuntime, string identifier, CancellationToken cancellationToken, params object[] args)
		{
			throw null;
		}

		[DebuggerStepThrough]
		public static ValueTask InvokeVoidAsync(this IJSRuntime jsRuntime, string identifier, TimeSpan timeout, params object[] args)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop.Infrastructure\DotNetDispatcher.cs
namespace Microsoft.JSInterop.Infrastructure
{
	public static class DotNetDispatcher
	{
		public static void BeginInvokeDotNet(JSRuntime jsRuntime, DotNetInvocationInfo invocationInfo, string argsJson)
		{
		}

		public static void EndInvokeJS(JSRuntime jsRuntime, string arguments)
		{
		}

		public static string Invoke(JSRuntime jsRuntime, in DotNetInvocationInfo invocationInfo, string argsJson)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop.Infrastructure\DotNetInvocationInfo.cs
using System.Runtime.CompilerServices;

namespace Microsoft.JSInterop.Infrastructure
{
	public readonly struct DotNetInvocationInfo
	{
		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public string AssemblyName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string CallId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public long DotNetObjectId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string MethodIdentifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DotNetInvocationInfo(string assemblyName, string methodIdentifier, long dotNetObjectId, string callId)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop.Infrastructure\DotNetInvocationResult.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.JSInterop.Infrastructure
{
	public readonly struct DotNetInvocationResult
	{
		private readonly object _dummy;

		private readonly int _dummyPrimitive;

		public string ErrorKind
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Exception Exception
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object Result
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool Success
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DotNetInvocationResult(Exception exception, string errorKind)
		{
			throw null;
		}

		public DotNetInvocationResult(object result)
		{
			throw null;
		}
	}
}


