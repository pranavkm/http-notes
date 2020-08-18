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
		public static IWebHost Start(RequestDelegate app)
		{
			throw null;
		}

		public static IWebHost Start(string? url, RequestDelegate app)
		{
			throw null;
		}

		public static IWebHost Start(Action<IRouteBuilder> routeBuilder)
		{
			throw null;
		}

		public static IWebHost Start(string? url, Action<IRouteBuilder> routeBuilder)
		{
			throw null;
		}

		public static IWebHost StartWith(Action<IApplicationBuilder> app)
		{
			throw null;
		}

		public static IWebHost StartWith(string? url, Action<IApplicationBuilder> app)
		{
			throw null;
		}

		public static IWebHostBuilder CreateDefaultBuilder()
		{
			throw null;
		}

		public static IWebHostBuilder CreateDefaultBuilder(string[]? args)
		{
			throw null;
		}

		public static IWebHostBuilder CreateDefaultBuilder<TStartup>(string[] args) where TStartup : class
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
				throw null;
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
				throw null;
			}
		}

		public string? HeaderName
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public AntiforgeryOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\AntiforgeryTokenSet.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Antiforgery
{
	public class AntiforgeryTokenSet
	{
		public string? RequestToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string FormFieldName
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? HeaderName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? CookieToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AntiforgeryTokenSet(string? requestToken, string? cookieToken, string formFieldName, string? headerName)
		{
			throw null;
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
			throw null;
		}

		public AntiforgeryValidationException(string message, Exception? innerException)
		{
			throw null;
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

		Task ValidateRequestAsync(HttpContext httpContext);

		void SetCookieTokenAndHeader(HttpContext httpContext);
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
		AntiforgeryToken? CookieToken
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

		AntiforgeryToken? NewCookieToken
		{
			get;
			set;
		}

		string? NewCookieTokenString
		{
			get;
			set;
		}

		AntiforgeryToken? NewRequestToken
		{
			get;
			set;
		}

		string? NewRequestTokenString
		{
			get;
			set;
		}

		AntiforgeryToken? RequestToken
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Antiforgery\Microsoft.AspNetCore.Antiforgery\IAntiforgeryTokenGenerator.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Antiforgery
{
	internal interface IAntiforgeryTokenGenerator
	{
		AntiforgeryToken GenerateCookieToken();

		AntiforgeryToken GenerateRequestToken(HttpContext httpContext, AntiforgeryToken cookieToken);

		bool IsCookieTokenValid(AntiforgeryToken? cookieToken);

		bool TryValidateTokenSet(HttpContext httpContext, AntiforgeryToken cookieToken, AntiforgeryToken requestToken, [NotNullWhen(false)] out string? message);
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
		string? GetCookieToken(HttpContext httpContext);

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
		string? ExtractClaimUid(ClaimsPrincipal claimsPrincipal);
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
				throw null;
			}
		}

		public AuthenticationProperties? Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? ReturnUrl
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string ReturnUrlParameter
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public AccessDeniedContext(HttpContext context, AuthenticationScheme scheme, RemoteAuthenticationOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\AuthenticationBuilder.cs
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationBuilder
	{
		private class EnsureSignInScheme<TOptions> : IPostConfigureOptions<TOptions> where TOptions : RemoteAuthenticationOptions
		{
			public EnsureSignInScheme(IOptions<AuthenticationOptions> authOptions)
			{
				throw null;
			}

			public void PostConfigure(string name, TOptions options)
			{
				throw null;
			}
		}

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
			throw null;
		}

		public virtual AuthenticationBuilder AddScheme<TOptions, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions) where TOptions : AuthenticationSchemeOptions, new()where THandler : AuthenticationHandler<TOptions>
		{
			throw null;
		}

		public virtual AuthenticationBuilder AddScheme<TOptions, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] THandler>(string authenticationScheme, Action<TOptions>? configureOptions) where TOptions : AuthenticationSchemeOptions, new()where THandler : AuthenticationHandler<TOptions>
		{
			throw null;
		}

		public virtual AuthenticationBuilder AddRemoteScheme<TOptions, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions) where TOptions : RemoteAuthenticationOptions, new()where THandler : RemoteAuthenticationHandler<TOptions>
		{
			throw null;
		}

		public virtual AuthenticationBuilder AddPolicyScheme(string authenticationScheme, string? displayName, Action<PolicySchemeOptions> configureOptions)
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
		public AuthenticationScheme Scheme
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

		protected HttpContext Context
		{
			[CompilerGenerated]
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

		protected ILogger Logger
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

		protected ISystemClock Clock
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

		protected virtual object? Events
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected virtual string ClaimsIssuer
		{
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

		protected AuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(AuthenticationHandler<>._003CInitializeAsync_003Ed__42))]
		[DebuggerStepThrough]
		public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(AuthenticationHandler<>._003CInitializeEventsAsync_003Ed__43))]
		[DebuggerStepThrough]
		protected virtual Task InitializeEventsAsync()
		{
			throw null;
		}

		protected virtual Task<object> CreateEventsAsync()
		{
			throw null;
		}

		protected virtual Task InitializeHandlerAsync()
		{
			throw null;
		}

		protected string BuildRedirectUri(string targetPath)
		{
			throw null;
		}

		protected virtual string? ResolveTarget(string? scheme)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(AuthenticationHandler<>._003CAuthenticateAsync_003Ed__48))]
		[DebuggerStepThrough]
		public Task<AuthenticateResult> AuthenticateAsync()
		{
			throw null;
		}

		protected Task<AuthenticateResult> HandleAuthenticateOnceAsync()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(AuthenticationHandler<>._003CHandleAuthenticateOnceSafeAsync_003Ed__50))]
		[DebuggerStepThrough]
		protected Task<AuthenticateResult> HandleAuthenticateOnceSafeAsync()
		{
			throw null;
		}

		protected abstract Task<AuthenticateResult> HandleAuthenticateAsync();

		protected virtual Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected virtual Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(AuthenticationHandler<>._003CChallengeAsync_003Ed__54))]
		[DebuggerStepThrough]
		public Task ChallengeAsync(AuthenticationProperties? properties)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(AuthenticationHandler<>._003CForbidAsync_003Ed__55))]
		[DebuggerStepThrough]
		public Task ForbidAsync(AuthenticationProperties? properties)
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
				throw null;
			}
		}

		public AuthenticationMiddleware(RequestDelegate next, IAuthenticationSchemeProvider schemes)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__6))]
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
		public string? ClaimsIssuer
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public object? Events
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public Type? EventsType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? ForwardDefault
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? ForwardAuthenticate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? ForwardChallenge
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? ForwardForbid
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? ForwardSignIn
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? ForwardSignOut
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public Func<HttpContext, string>? ForwardDefaultSelector
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public virtual void Validate()
		{
			throw null;
		}

		public virtual void Validate(string scheme)
		{
			throw null;
		}

		public AuthenticationSchemeOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\Base64UrlTextEncoder.cs
namespace Microsoft.AspNetCore.Authentication
{
	public static class Base64UrlTextEncoder
	{
		public static string Encode(byte[] data)
		{
			throw null;
		}

		public static byte[] Decode(string text)
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
		public AuthenticationScheme Scheme
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

		public HttpContext HttpContext
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

		protected BaseContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
		{
			throw null;
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
				throw null;
			}
		}

		protected HandleRequestContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
		{
			throw null;
		}

		public void HandleResponse()
		{
			throw null;
		}

		public void SkipHandler()
		{
			throw null;
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

		public new static HandleRequestResult Success(AuthenticationTicket ticket)
		{
			throw null;
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

		public static HandleRequestResult SkipHandler()
		{
			throw null;
		}

		public new static HandleRequestResult NoResult()
		{
			throw null;
		}

		public HandleRequestResult()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\IDataSerializer.cs
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IDataSerializer<TModel>
	{
		byte[] Serialize(TModel model);

		[return: MaybeNull]
		TModel Deserialize(byte[] data);
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\ISecureDataFormat.cs
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Authentication
{
	public interface ISecureDataFormat<TData>
	{
		string Protect(TData data);

		string Protect(TData data, string? purpose);

		[return: MaybeNull]
		TData Unprotect(string protectedText);

		[return: MaybeNull]
		TData Unprotect(string protectedText, string? purpose);
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
		public static string? GetString(this JsonElement element, string key)
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
		{
			throw null;
		}

		protected override Task HandleChallengeAsync(AuthenticationProperties? properties)
		{
			throw null;
		}

		protected override Task HandleForbiddenAsync(AuthenticationProperties? properties)
		{
			throw null;
		}

		protected override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
		{
			throw null;
		}

		protected override Task HandleSignOutAsync(AuthenticationProperties? properties)
		{
			throw null;
		}

		protected override Task<AuthenticateResult> HandleAuthenticateAsync()
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
		public PolicySchemeOptions()
		{
			throw null;
		}
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
		public virtual ClaimsPrincipal? Principal
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		protected PrincipalContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties? properties)
		{
			throw null;
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
				throw null;
			}
		}

		protected PropertiesContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties? properties)
		{
			throw null;
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
		{
			throw null;
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

		public virtual byte[] Serialize(AuthenticationProperties model)
		{
			throw null;
		}

		public virtual AuthenticationProperties? Deserialize(byte[] data)
		{
			throw null;
		}

		public virtual void Write(BinaryWriter writer, AuthenticationProperties properties)
		{
			throw null;
		}

		public virtual AuthenticationProperties? Read(BinaryReader reader)
		{
			throw null;
		}

		public PropertiesSerializer()
		{
			throw null;
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
				throw null;
			}
		}

		public RedirectContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties properties, string redirectUri)
		{
			throw null;
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
		public ClaimsPrincipal? Principal
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		protected RemoteAuthenticationContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties? properties)
		{
			throw null;
		}

		public void Success()
		{
			throw null;
		}

		public void Fail(Exception failure)
		{
			throw null;
		}

		public void Fail(string failureMessage)
		{
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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

		public RemoteAuthenticationEvents()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\RemoteAuthenticationHandler.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class RemoteAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationRequestHandler, IAuthenticationHandler where TOptions : RemoteAuthenticationOptions, new()
	{
		protected string? SignInScheme
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
		}

		protected new RemoteAuthenticationEvents Events
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		protected RemoteAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
		{
			throw null;
		}

		protected override Task<object> CreateEventsAsync()
		{
			throw null;
		}

		public virtual Task<bool> ShouldHandleRequestAsync()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(RemoteAuthenticationHandler<>._003CHandleRequestAsync_003Ed__11))]
		[DebuggerStepThrough]
		public virtual Task<bool> HandleRequestAsync()
		{
			throw null;
		}

		protected abstract Task<HandleRequestResult> HandleRemoteAuthenticateAsync();

		[AsyncStateMachine(typeof(RemoteAuthenticationHandler<>._003CHandleAuthenticateAsync_003Ed__13))]
		[DebuggerStepThrough]
		protected override Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			throw null;
		}

		protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			throw null;
		}

		protected virtual void GenerateCorrelationId(AuthenticationProperties properties)
		{
			throw null;
		}

		protected virtual bool ValidateCorrelationId(AuthenticationProperties properties)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(RemoteAuthenticationHandler<>._003CHandleAccessDeniedErrorAsync_003Ed__17))]
		[DebuggerStepThrough]
		protected virtual Task<HandleRequestResult> HandleAccessDeniedErrorAsync(AuthenticationProperties properties)
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
		private class CorrelationCookieBuilder : RequestPathBaseCookieBuilder
		{
			protected override string AdditionalPath
			{
				get
				{
					throw null;
				}
			}

			public CorrelationCookieBuilder(RemoteAuthenticationOptions remoteAuthenticationOptions)
			{
				throw null;
			}

			public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
			{
				throw null;
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
				throw null;
			}
		}

		public HttpMessageHandler? BackchannelHttpHandler
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public IDataProtectionProvider? DataProtectionProvider
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
			}
		}

		public string? SignInScheme
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public RemoteAuthenticationOptions()
		{
			throw null;
		}

		public override void Validate(string scheme)
		{
			throw null;
		}

		public override void Validate()
		{
			throw null;
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
		public Exception? Failure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public AuthenticationProperties? Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public RemoteFailureContext(HttpContext context, AuthenticationScheme scheme, RemoteAuthenticationOptions options, Exception failure)
		{
			throw null;
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
		protected virtual string? AdditionalPath
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

		public RequestPathBaseCookieBuilder()
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
		public ClaimsPrincipal? Principal
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
		{
			throw null;
		}

		public void Success()
		{
			throw null;
		}

		public void NoResult()
		{
			throw null;
		}

		public void Fail(Exception failure)
		{
			throw null;
		}

		public void Fail(string failureMessage)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\SecureDataFormat.cs
using Microsoft.AspNetCore.DataProtection;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Authentication
{
	public class SecureDataFormat<TData> : ISecureDataFormat<TData>
	{
		public SecureDataFormat(IDataSerializer<TData> serializer, IDataProtector protector)
		{
			throw null;
		}

		public string Protect(TData data)
		{
			throw null;
		}

		public string Protect(TData data, string? purpose)
		{
			throw null;
		}

		[return: MaybeNull]
		public TData Unprotect(string protectedText)
		{
			throw null;
		}

		[return: MaybeNull]
		public TData Unprotect(string protectedText, string? purpose)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\SignInAuthenticationHandler.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class SignInAuthenticationHandler<TOptions> : SignOutAuthenticationHandler<TOptions>, IAuthenticationSignInHandler, IAuthenticationSignOutHandler, IAuthenticationHandler where TOptions : AuthenticationSchemeOptions, new()
	{
		[System.Runtime.CompilerServices.NullableContext(1)]
		public SignInAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
		{
			throw null;
		}

		public virtual Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
		{
			throw null;
		}

		protected abstract Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties);
	}
}


// Microsoft.AspNetCore.Authentication\Microsoft.AspNetCore.Authentication\SignOutAuthenticationHandler.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public abstract class SignOutAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationSignOutHandler, IAuthenticationHandler where TOptions : AuthenticationSchemeOptions, new()
	{
		public SignOutAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
		{
			throw null;
		}

		public virtual Task SignOutAsync(AuthenticationProperties? properties)
		{
			throw null;
		}

		protected abstract Task HandleSignOutAsync(AuthenticationProperties? properties);
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

		public SystemClock()
		{
			throw null;
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
		{
			throw null;
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
		public string? ReturnUri
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public TicketReceivedContext(HttpContext context, AuthenticationScheme scheme, RemoteAuthenticationOptions options, AuthenticationTicket ticket)
		{
			throw null;
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

		public virtual byte[] Serialize(AuthenticationTicket ticket)
		{
			throw null;
		}

		public virtual AuthenticationTicket? Deserialize(byte[] data)
		{
			throw null;
		}

		public virtual void Write(BinaryWriter writer, AuthenticationTicket ticket)
		{
			throw null;
		}

		protected virtual void WriteIdentity(BinaryWriter writer, ClaimsIdentity identity)
		{
			throw null;
		}

		protected virtual void WriteClaim(BinaryWriter writer, Claim claim)
		{
			throw null;
		}

		public virtual AuthenticationTicket? Read(BinaryReader reader)
		{
			throw null;
		}

		protected virtual ClaimsIdentity ReadIdentity(BinaryReader reader)
		{
			throw null;
		}

		protected virtual Claim ReadClaim(BinaryReader reader, ClaimsIdentity identity)
		{
			throw null;
		}

		public TicketSerializer()
		{
			throw null;
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
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class AuthenticationServiceCollectionExtensions
	{
		private class EnsureSignInScheme<TOptions> : IPostConfigureOptions<TOptions> where TOptions : RemoteAuthenticationOptions
		{
			public EnsureSignInScheme(IOptions<AuthenticationOptions> authOptions)
			{
				throw null;
			}

			public void PostConfigure(string name, TOptions options)
			{
				throw null;
			}
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services)
		{
			throw null;
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, string defaultScheme)
		{
			throw null;
		}

		public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, Action<AuthenticationOptions> configureOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticateResult.cs
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticateResult
	{
		[MemberNotNullWhen(true, "Ticket")]
		public bool Succeeded
		{
			[MemberNotNullWhen(true, "Ticket")]
			get
			{
				throw null;
			}
		}

		public AuthenticationTicket? Ticket
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
				throw null;
			}
		}

		public ClaimsPrincipal? Principal
		{
			get
			{
				throw null;
			}
		}

		public AuthenticationProperties? Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
				throw null;
			}
		}

		public Exception? Failure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			protected set
			{
				throw null;
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
				throw null;
			}
		}

		protected AuthenticateResult()
		{
			throw null;
		}

		public AuthenticateResult Clone()
		{
			throw null;
		}

		public static AuthenticateResult Success(AuthenticationTicket ticket)
		{
			throw null;
		}

		public static AuthenticateResult NoResult()
		{
			throw null;
		}

		public static AuthenticateResult Fail(Exception? failure)
		{
			throw null;
		}

		public static AuthenticateResult Fail(Exception? failure, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static AuthenticateResult Fail(string? failureMessage)
		{
			throw null;
		}

		public static AuthenticateResult Fail(string? failureMessage, AuthenticationProperties? properties)
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

		public static Task<AuthenticateResult> AuthenticateAsync(this HttpContext context, string? scheme)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context, string? scheme)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task ChallengeAsync(this HttpContext context, string? scheme, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context, string? scheme)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task ForbidAsync(this HttpContext context, string? scheme, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, string? scheme, ClaimsPrincipal principal)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task SignInAsync(this HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context, string? scheme)
		{
			throw null;
		}

		public static Task SignOutAsync(this HttpContext context, string? scheme, AuthenticationProperties? properties)
		{
			throw null;
		}

		public static Task<string?> GetTokenAsync(this HttpContext context, string? scheme, string tokenName)
		{
			throw null;
		}

		public static Task<string?> GetTokenAsync(this HttpContext context, string tokenName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationOptions.cs
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationOptions
	{
		public IEnumerable<AuthenticationSchemeBuilder> Schemes
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			get
			{
				throw null;
			}
		}

		public IDictionary<string, AuthenticationSchemeBuilder> SchemeMap
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? DefaultScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? DefaultAuthenticateScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? DefaultSignInScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? DefaultSignOutScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? DefaultChallengeScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? DefaultForbidScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public void AddScheme(string name, Action<AuthenticationSchemeBuilder> configureBuilder)
		{
			throw null;
		}

		public void AddScheme<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] THandler>(string name, string displayName) where THandler : IAuthenticationHandler
		{
			throw null;
		}

		public AuthenticationOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationProperties.cs
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationProperties
	{
		public IDictionary<string, string?> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IDictionary<string, object?> Parameters
		{
			[CompilerGenerated]
			get
			{
				throw null;
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
				throw null;
			}
		}

		public string? RedirectUri
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public bool? AllowRefresh
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public AuthenticationProperties()
		{
			throw null;
		}

		public AuthenticationProperties(IDictionary<string, string?> items)
		{
			throw null;
		}

		public AuthenticationProperties(IDictionary<string, string?>? items, IDictionary<string, object?>? parameters)
		{
			throw null;
		}

		public AuthenticationProperties Clone()
		{
			throw null;
		}

		public string? GetString(string key)
		{
			throw null;
		}

		public void SetString(string key, string? value)
		{
			throw null;
		}

		[return: MaybeNull]
		public T GetParameter<T>(string key)
		{
			throw null;
		}

		public void SetParameter<T>(string key, [MaybeNull] T value)
		{
			throw null;
		}

		protected bool? GetBool(string key)
		{
			throw null;
		}

		protected void SetBool(string key, bool? value)
		{
			throw null;
		}

		protected DateTimeOffset? GetDateTimeOffset(string key)
		{
			throw null;
		}

		protected void SetDateTimeOffset(string key, DateTimeOffset? value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationScheme.cs
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationScheme
	{
		public string Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? DisplayName
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
		public Type HandlerType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticationScheme(string name, string? displayName, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type handlerType)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationSchemeBuilder.cs
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationSchemeBuilder
	{
		public string Name
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? DisplayName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
		public Type? HandlerType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public AuthenticationSchemeBuilder(string name)
		{
			throw null;
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

		public AuthenticationTicket(ClaimsPrincipal principal, AuthenticationProperties? properties, string authenticationScheme)
		{
			throw null;
		}

		public AuthenticationTicket(ClaimsPrincipal principal, string authenticationScheme)
		{
			throw null;
		}

		public AuthenticationTicket Clone()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationToken.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Authentication
{
	public class AuthenticationToken
	{
		public string? Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public AuthenticationToken()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\AuthenticationTokenExtensions.cs
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public static class AuthenticationTokenExtensions
	{
		public static void StoreTokens(this AuthenticationProperties properties, IEnumerable<AuthenticationToken> tokens)
		{
			throw null;
		}

		public static string? GetTokenValue(this AuthenticationProperties properties, string tokenName)
		{
			throw null;
		}

		public static bool UpdateTokenValue(this AuthenticationProperties properties, string tokenName, string tokenValue)
		{
			throw null;
		}

		public static IEnumerable<AuthenticationToken> GetTokens(this AuthenticationProperties properties)
		{
			throw null;
		}

		public static Task<string?> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string tokenName)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CGetTokenAsync_003Ed__7))]
		[DebuggerStepThrough]
		public static Task<string?> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string? scheme, string tokenName)
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
		PathString OriginalPathBase
		{
			get;
			set;
		}

		PathString OriginalPath
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
		Task InitializeAsync(AuthenticationScheme scheme, HttpContext context);

		Task<AuthenticateResult> AuthenticateAsync();

		Task ChallengeAsync(AuthenticationProperties? properties);

		Task ForbidAsync(AuthenticationProperties? properties);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationHandlerProvider.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationHandlerProvider
	{
		Task<IAuthenticationHandler?> GetHandlerAsync(HttpContext context, string authenticationScheme);
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
		Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync();

		Task<AuthenticationScheme?> GetSchemeAsync(string name);

		Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync();

		Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync();

		Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync();

		Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync();

		Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync();

		void AddScheme(AuthenticationScheme scheme);

		bool TryAddScheme(AuthenticationScheme scheme)
		{
			throw null;
		}

		void RemoveScheme(string name);

		Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync();
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
		Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme);

		Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties);

		Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties);

		Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties);

		Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationSignInHandler.cs
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationSignInHandler : IAuthenticationSignOutHandler, IAuthenticationHandler
	{
		Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties);
	}
}


// Microsoft.AspNetCore.Authentication.Abstractions\Microsoft.AspNetCore.Authentication\IAuthenticationSignOutHandler.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
	public interface IAuthenticationSignOutHandler : IAuthenticationHandler
	{
		Task SignOutAsync(AuthenticationProperties? properties);
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
		public AllowAnonymousAttribute()
		{
			throw null;
		}
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public abstract class AuthorizationHandler<TRequirement> : IAuthorizationHandler where TRequirement : IAuthorizationRequirement
	{
		[AsyncStateMachine(typeof(AuthorizationHandler<>._003CHandleAsync_003Ed__0))]
		[DebuggerStepThrough]
		public virtual Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}

		protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement);

		protected AuthorizationHandler()
		{
			throw null;
		}
	}
	public abstract class AuthorizationHandler<TRequirement, TResource> : IAuthorizationHandler where TRequirement : IAuthorizationRequirement
	{
		[AsyncStateMachine(typeof(AuthorizationHandler<, >._003CHandleAsync_003Ed__0))]
		[DebuggerStepThrough]
		public virtual Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}

		protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement, TResource resource);

		protected AuthorizationHandler()
		{
			throw null;
		}
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
		public virtual IEnumerable<IAuthorizationRequirement> Requirements
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

		public virtual object? Resource
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
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

		public AuthorizationHandlerContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object? resource)
		{
			throw null;
		}

		public virtual void Fail()
		{
			throw null;
		}

		public virtual void Succeed(IAuthorizationRequirement requirement)
		{
			throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public AuthorizationPolicy? FallbackPolicy
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public void AddPolicy(string name, AuthorizationPolicy policy)
		{
			throw null;
		}

		public void AddPolicy(string name, Action<AuthorizationPolicyBuilder> configurePolicy)
		{
			throw null;
		}

		public AuthorizationPolicy? GetPolicy(string name)
		{
			throw null;
		}

		public AuthorizationOptions()
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
		public IReadOnlyList<IAuthorizationRequirement> Requirements
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<string> AuthenticationSchemes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthorizationPolicy(IEnumerable<IAuthorizationRequirement> requirements, IEnumerable<string> authenticationSchemes)
		{
			throw null;
		}

		public static AuthorizationPolicy Combine(params AuthorizationPolicy[] policies)
		{
			throw null;
		}

		public static AuthorizationPolicy Combine(IEnumerable<AuthorizationPolicy> policies)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CCombineAsync_003Ed__9))]
		[DebuggerStepThrough]
		public static Task<AuthorizationPolicy?> CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizeData> authorizeData)
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public AuthorizationPolicyBuilder(params string[] authenticationSchemes)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder(AuthorizationPolicy policy)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder AddAuthenticationSchemes(params string[] schemes)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder AddRequirements(params IAuthorizationRequirement[] requirements)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder Combine(AuthorizationPolicy policy)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireClaim(string claimType, params string[] allowedValues)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireClaim(string claimType, IEnumerable<string> allowedValues)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireClaim(string claimType)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireRole(params string[] roles)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireRole(IEnumerable<string> roles)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireUserName(string userName)
		{
			throw null;
		}

		public AuthorizationPolicyBuilder RequireAuthenticatedUser()
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

		public AuthorizationPolicy Build()
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
		public bool Succeeded
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthorizationFailure? Failure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static AuthorizationResult Success()
		{
			throw null;
		}

		public static AuthorizationResult Failed(AuthorizationFailure failure)
		{
			throw null;
		}

		public static AuthorizationResult Failed()
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
		public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object resource, IAuthorizationRequirement requirement)
		{
			throw null;
		}

		public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object? resource, AuthorizationPolicy policy)
		{
			throw null;
		}

		public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, AuthorizationPolicy policy)
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
		public string? Policy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? Roles
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? AuthenticationSchemes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public AuthorizeAttribute()
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public AuthorizeAttribute(string policy)
		{
			throw null;
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

		public DefaultAuthorizationEvaluator()
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
		public virtual AuthorizationHandlerContext CreateContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object? resource)
		{
			throw null;
		}

		public DefaultAuthorizationHandlerContextFactory()
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
			throw null;
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
			throw null;
		}

		public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
		{
			throw null;
		}

		public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
		{
			throw null;
		}

		public virtual Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
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
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class DefaultAuthorizationService : IAuthorizationService
	{
		public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IAuthorizationHandlerProvider handlers, ILogger<DefaultAuthorizationService> logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator, IOptions<AuthorizationOptions> options)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CAuthorizeAsync_003Ed__7))]
		[DebuggerStepThrough]
		public virtual Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CAuthorizeAsync_003Ed__8))]
		[DebuggerStepThrough]
		public virtual Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName)
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
		AuthorizationHandlerContext CreateContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object? resource);
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
		Task<AuthorizationPolicy?> GetPolicyAsync(string policyName);

		Task<AuthorizationPolicy> GetDefaultPolicyAsync();

		Task<AuthorizationPolicy?> GetFallbackPolicyAsync();
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
		Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements);

		Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName);
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
			throw null;
		}

		public AssertionRequirement(Func<AuthorizationHandlerContext, Task<bool>> handler)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CHandleAsync_003Ed__5))]
		[DebuggerStepThrough]
		public Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}

		public override string ToString()
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
		public string ClaimType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IEnumerable<string>? AllowedValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ClaimsAuthorizationRequirement(string claimType, IEnumerable<string>? allowedValues)
		{
			throw null;
		}

		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ClaimsAuthorizationRequirement requirement)
		{
			throw null;
		}

		public override string ToString()
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

		public override string ToString()
		{
			throw null;
		}

		public DenyAnonymousAuthorizationRequirement()
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
			throw null;
		}

		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NameAuthorizationRequirement requirement)
		{
			throw null;
		}

		public override string ToString()
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
				throw null;
			}
		}

		public override string ToString()
		{
			throw null;
		}

		public OperationAuthorizationRequirement()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization\Microsoft.AspNetCore.Authorization.Infrastructure\PassThroughAuthorizationHandler.cs
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Infrastructure
{
	public class PassThroughAuthorizationHandler : IAuthorizationHandler
	{
		[AsyncStateMachine(typeof(_003CHandleAsync_003Ed__0))]
		[DebuggerStepThrough]
		public Task HandleAsync(AuthorizationHandlerContext context)
		{
			throw null;
		}

		public PassThroughAuthorizationHandler()
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
			throw null;
		}

		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
		{
			throw null;
		}

		public override string ToString()
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public class AuthorizationMiddleware
	{
		public AuthorizationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__6))]
		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Authorization\IAuthorizationMiddlewareResultHandler.cs
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
	public interface IAuthorizationMiddlewareResultHandler
	{
		Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult);
	}
}


// Microsoft.AspNetCore.Authorization.Policy\Microsoft.AspNetCore.Authorization.Policy\AuthorizationMiddlewareResultHandler.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Policy
{
	public class AuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
	{
		[AsyncStateMachine(typeof(_003CHandleAsync_003Ed__0))]
		[DebuggerStepThrough]
		public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
		{
			throw null;
		}

		public AuthorizationMiddlewareResultHandler()
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

		Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object? resource);
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

		public AuthorizationFailure? AuthorizationFailure
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static PolicyAuthorizationResult Challenge()
		{
			throw null;
		}

		public static PolicyAuthorizationResult Forbid()
		{
			throw null;
		}

		public static PolicyAuthorizationResult Forbid(AuthorizationFailure? authorizationFailure)
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization.Policy
{
	public class PolicyEvaluator : IPolicyEvaluator
	{
		public PolicyEvaluator(IAuthorizationService authorization)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CAuthenticateAsync_003Ed__2))]
		[DebuggerStepThrough]
		public virtual Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CAuthorizeAsync_003Ed__3))]
		[DebuggerStepThrough]
		public virtual Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object? resource)
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

		public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder, params string[] policyNames) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder, params IAuthorizeData[] authorizeData) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder AllowAnonymous<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
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
		public static IServiceCollection AddAuthorizationPolicyEvaluator(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddAuthorization(this IServiceCollection services)
		{
			throw null;
		}

		public static IServiceCollection AddAuthorization(this IServiceCollection services, Action<AuthorizationOptions> configure)
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
		public string Element
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? Suffix
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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

		public string ChangeAttribute
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public BindElementAttribute(string element, string? suffix, string valueAttribute, string changeAttribute)
		{
			throw null;
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
		public string? Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public CascadingParameterAttribute()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\CascadingParameterState.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	internal readonly struct CascadingParameterState
	{
		private readonly struct ReflectedCascadingParameterInfo
		{
			public string ConsumerValueName
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public string? SupplierValueName
			{
				[System.Runtime.CompilerServices.NullableContext(2)]
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public Type ValueType
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public ReflectedCascadingParameterInfo(string consumerValueName, Type valueType, string? supplierValueName)
			{
				throw null;
			}
		}

		private static readonly ConcurrentDictionary<Type, ReflectedCascadingParameterInfo[]> _cachedInfos;

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
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public class CascadingValue<TValue> : ICascadingValueComponent, IComponent
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
				throw null;
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
				throw null;
			}
		}

		[Parameter]
		public string? Name
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		object ICascadingValueComponent.CurrentValue
		{
			get
			{
				throw null;
			}
		}

		bool ICascadingValueComponent.CurrentValueIsFixed
		{
			get
			{
				throw null;
			}
		}

		public void Attach(RenderHandle renderHandle)
		{
			throw null;
		}

		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		bool ICascadingValueComponent.CanSupplyValue(Type requestedType, string requestedName)
		{
			throw null;
		}

		void ICascadingValueComponent.Subscribe(ComponentState subscriber)
		{
			throw null;
		}

		void ICascadingValueComponent.Unsubscribe(ComponentState subscriber)
		{
			throw null;
		}

		public CascadingValue()
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
		public object? Value
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ChangeEventArgs()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ComponentBase.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public abstract class ComponentBase : IComponent, IHandleEvent, IHandleAfterRender
	{
		public ComponentBase()
		{
			throw null;
		}

		protected virtual void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected virtual void OnInitialized()
		{
			throw null;
		}

		protected virtual Task OnInitializedAsync()
		{
			throw null;
		}

		protected virtual void OnParametersSet()
		{
			throw null;
		}

		protected virtual Task OnParametersSetAsync()
		{
			throw null;
		}

		protected void StateHasChanged()
		{
			throw null;
		}

		protected virtual bool ShouldRender()
		{
			throw null;
		}

		protected virtual void OnAfterRender(bool firstRender)
		{
			throw null;
		}

		protected virtual Task OnAfterRenderAsync(bool firstRender)
		{
			throw null;
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
			throw null;
		}

		public virtual Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		Task IHandleEvent.HandleEventAsync(EventCallbackWorkItem callback, object? arg)
		{
			throw null;
		}

		Task IHandleAfterRender.OnAfterRenderAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\Dispatcher.cs
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public abstract class Dispatcher
	{
		internal event UnhandledExceptionEventHandler? UnhandledException
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			add
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			remove
			{
				throw null;
			}
		}

		public static Dispatcher CreateDefault()
		{
			throw null;
		}

		public void AssertAccess()
		{
			throw null;
		}

		public abstract bool CheckAccess();

		public abstract Task InvokeAsync(Action workItem);

		public abstract Task InvokeAsync(Func<Task> workItem);

		public abstract Task<TResult> InvokeAsync<TResult>(Func<TResult> workItem);

		public abstract Task<TResult> InvokeAsync<TResult>(Func<Task<TResult>> workItem);

		protected void OnUnhandledException(UnhandledExceptionEventArgs e)
		{
			throw null;
		}

		protected Dispatcher()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ElementReference.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct ElementReference
	{
		private static long _nextIdForWebAssemblyOnly;

		public string Id
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ElementReferenceContext? Context
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ElementReference(string id, ElementReferenceContext? context)
		{
			throw null;
		}

		public ElementReference(string id)
		{
			throw null;
		}

		internal static ElementReference CreateWithUniqueId(ElementReferenceContext? context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ElementReferenceContext.cs
namespace Microsoft.AspNetCore.Components
{
	public abstract class ElementReferenceContext
	{
		protected ElementReferenceContext()
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
		public static readonly EventCallbackFactory Factory;

		public static readonly EventCallback Empty;

		internal readonly MulticastDelegate? Delegate;

		internal readonly IHandleEvent? Receiver;

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

		public EventCallback(IHandleEvent? receiver, MulticastDelegate? @delegate)
		{
			throw null;
		}

		public Task InvokeAsync(object arg)
		{
			throw null;
		}

		public Task InvokeAsync()
		{
			throw null;
		}

		object? IEventCallback.UnpackForRenderTree()
		{
			throw null;
		}
	}
	public readonly struct EventCallback<TValue> : IEventCallback
	{
		public static readonly EventCallback<TValue> Empty;

		internal readonly MulticastDelegate? Delegate;

		internal readonly IHandleEvent? Receiver;

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

		public EventCallback(IHandleEvent? receiver, MulticastDelegate? @delegate)
		{
			throw null;
		}

		public Task InvokeAsync(TValue arg)
		{
			throw null;
		}

		public Task InvokeAsync()
		{
			throw null;
		}

		internal EventCallback AsUntyped()
		{
			throw null;
		}

		object? IEventCallback.UnpackForRenderTree()
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

		public EventCallback Create(object receiver, Func<Task> callback)
		{
			throw null;
		}

		public EventCallback Create(object receiver, Func<object, Task> callback)
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

		public EventCallbackFactory()
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
		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<string?> setter, string existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<bool> setter, bool existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<bool?> setter, bool? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<int> setter, int existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<int?> setter, int? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<long> setter, long existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<short> setter, short existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<long?> setter, long? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<short?> setter, short? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<float> setter, float existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<float?> setter, float? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<double> setter, double existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<double?> setter, double? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<decimal> setter, decimal existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<decimal?> setter, decimal? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime> setter, DateTime existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime> setter, DateTime existingValue, string format, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime?> setter, DateTime? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTime?> setter, DateTime? existingValue, string format, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset> setter, DateTimeOffset existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset> setter, DateTimeOffset existingValue, string format, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset?> setter, DateTimeOffset? existingValue, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder(this EventCallbackFactory factory, object receiver, Action<DateTimeOffset?> setter, DateTimeOffset? existingValue, string format, CultureInfo? culture = null)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> CreateBinder<T>(this EventCallbackFactory factory, object receiver, Action<T> setter, T existingValue, CultureInfo? culture = null)
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
		public static EventCallback<EventArgs> Create(this EventCallbackFactory factory, object receiver, Action<EventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<EventArgs> Create(this EventCallbackFactory factory, object receiver, Func<EventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<ChangeEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<ChangeEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ChangeEventArgs, Task> callback)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\EventCallbackWorkItem.cs
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct EventCallbackWorkItem
	{
		public static readonly EventCallbackWorkItem Empty;

		private readonly MulticastDelegate? _delegate;

		[System.Runtime.CompilerServices.NullableContext(2)]
		public EventCallbackWorkItem(MulticastDelegate? @delegate)
		{
			throw null;
		}

		public Task InvokeAsync(object? arg)
		{
			throw null;
		}

		internal static Task InvokeAsync<T>(MulticastDelegate? @delegate, T arg)
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

		public Type EventArgsType
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

		public bool EnablePreventDefault
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public EventHandlerAttribute(string attributeName, Type eventArgsType)
		{
			throw null;
		}

		public EventHandlerAttribute(string attributeName, Type eventArgsType, bool enableStopPropagation, bool enablePreventDefault)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ICascadingValueComponent.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	internal interface ICascadingValueComponent
	{
		object? CurrentValue
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get;
		}

		bool CurrentValueIsFixed
		{
			get;
		}

		bool CanSupplyValue(Type valueType, string? valueName);

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


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\IComponentActivator.cs
using System;

namespace Microsoft.AspNetCore.Components
{
	public interface IComponentActivator
	{
		IComponent CreateInstance(Type componentType);
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

		object? UnpackForRenderTree();
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
		Task HandleEventAsync(EventCallbackWorkItem item, object? arg);
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\InjectAttribute.cs
using System;

namespace Microsoft.AspNetCore.Components
{
	[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
	public sealed class InjectAttribute : Attribute
	{
		public InjectAttribute()
		{
			throw null;
		}
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
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\LayoutComponentBase.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public abstract class LayoutComponentBase : ComponentBase
	{
		internal const string BodyPropertyName = "Body";

		[Parameter]
		public RenderFragment? Body
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected LayoutComponentBase()
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public void Attach(RenderHandle renderHandle)
		{
			throw null;
		}

		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		public LayoutView()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\LocationChangeException.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public sealed class LocationChangeException : Exception
	{
		[System.Runtime.CompilerServices.NullableContext(1)]
		public LocationChangeException(string message, Exception innerException)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\MarkupString.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct MarkupString
	{
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
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public event EventHandler<LocationChangedEventArgs> LocationChanged
		{
			add
			{
				throw null;
			}
			remove
			{
				throw null;
			}
		}

		public void NavigateTo(string uri, bool forceLoad = false)
		{
			throw null;
		}

		protected abstract void NavigateToCore(string uri, bool forceLoad);

		protected void Initialize(string baseUri, string uri)
		{
			throw null;
		}

		protected virtual void EnsureInitialized()
		{
			throw null;
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

		protected void NotifyLocationChanged(bool isInterceptedLink)
		{
			throw null;
		}

		protected NavigationManager()
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

		void IDisposable.Dispose()
		{
			throw null;
		}

		protected virtual void Dispose(bool disposing)
		{
			throw null;
		}

		protected OwningComponentBase()
		{
			throw null;
		}
	}
	public abstract class OwningComponentBase<TService> : OwningComponentBase, IDisposable where TService : notnull
	{
		protected TService Service
		{
			get
			{
				throw null;
			}
		}

		protected OwningComponentBase()
		{
			throw null;
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
				throw null;
			}
		}

		public ParameterAttribute()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ParameterValue.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct ParameterValue
	{
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

		public bool Cascading
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal ParameterValue(string name, object value, bool cascading)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components\ParameterView.cs
using Microsoft.AspNetCore.Components.Rendering;
using Microsoft.AspNetCore.Components.RenderTree;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public readonly struct ParameterView
	{
		public struct Enumerator
		{
			private RenderTreeFrameParameterEnumerator _directParamsEnumerator;

			private CascadingParameterEnumerator _cascadingParameterEnumerator;

			private bool _isEnumeratingDirectParams;

			public ParameterValue Current
			{
				get
				{
					throw null;
				}
			}

			[System.Runtime.CompilerServices.NullableContext(1)]
			internal Enumerator(RenderTreeFrame[] frames, int ownerIndex, IReadOnlyList<CascadingParameterState> cascadingParameters)
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}
		}

		private struct RenderTreeFrameParameterEnumerator
		{
			private readonly RenderTreeFrame[] _frames;

			private readonly int _ownerIndex;

			private readonly int _ownerDescendantsEndIndexExcl;

			private int _currentIndex;

			private ParameterValue _current;

			public ParameterValue Current
			{
				get
				{
					throw null;
				}
			}

			internal RenderTreeFrameParameterEnumerator(RenderTreeFrame[] frames, int ownerIndex)
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}
		}

		private struct CascadingParameterEnumerator
		{
			private readonly IReadOnlyList<CascadingParameterState> _cascadingParameters;

			private int _currentIndex;

			private ParameterValue _current;

			public ParameterValue Current
			{
				get
				{
					throw null;
				}
			}

			public CascadingParameterEnumerator(IReadOnlyList<CascadingParameterState> cascadingParameters)
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}
		}

		private const string GeneratedParameterViewElementName = "__ARTIFICIAL_PARAMETER_VIEW";

		private static readonly RenderTreeFrame[] _emptyFrames;

		private static readonly ParameterView _empty;

		private readonly ParameterViewLifetime _lifetime;

		private readonly RenderTreeFrame[] _frames;

		private readonly int _ownerIndex;

		private readonly IReadOnlyList<CascadingParameterState> _cascadingParameters;

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

		internal ParameterView(in ParameterViewLifetime lifetime, RenderTreeFrame[] frames, int ownerIndex)
		{
			throw null;
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		public bool TryGetValue<TValue>(string parameterName, [MaybeNullWhen(false)] out TValue result)
		{
			throw null;
		}

		[return: MaybeNull]
		public TValue GetValueOrDefault<TValue>(string parameterName)
		{
			throw null;
		}

		public TValue GetValueOrDefault<TValue>(string parameterName, TValue defaultValue)
		{
			throw null;
		}

		public IReadOnlyDictionary<string, object> ToDictionary()
		{
			throw null;
		}

		internal ParameterView WithCascadingParameters(IReadOnlyList<CascadingParameterState> cascadingParameters)
		{
			throw null;
		}

		internal bool DefinitelyEquals(ParameterView oldParameters)
		{
			throw null;
		}

		internal void CaptureSnapshot(ArrayBuilder<RenderTreeFrame> builder)
		{
			throw null;
		}

		public static ParameterView FromDictionary(IDictionary<string, object> parameters)
		{
			throw null;
		}

		public void SetParameterProperties(object target)
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
		private readonly Renderer _renderer;

		private readonly int _componentId;

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

		internal RenderHandle(Renderer renderer, int componentId)
		{
			throw null;
		}

		public void Render(RenderFragment renderFragment)
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
			throw null;
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
			throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public RouteView()
		{
			throw null;
		}

		public void Attach(RenderHandle renderHandle)
		{
			throw null;
		}

		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		protected virtual void Render(RenderTreeBuilder builder)
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
		public static T TypeCheck<T>(T value)
		{
			throw null;
		}

		public static EventCallback<T> CreateInferredEventCallback<T>(object receiver, Action<T> callback, T value)
		{
			throw null;
		}

		public static EventCallback<T> CreateInferredEventCallback<T>(object receiver, Func<T, Task> callback, T value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Reflection\IPropertySetter.cs
namespace Microsoft.AspNetCore.Components.Reflection
{
	internal interface IPropertySetter
	{
		bool Cascading
		{
			get;
		}

		void SetValue(object target, object value);
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

		public KeyedItemInfo WithOldSiblingIndex(int oldSiblingIndex)
		{
			throw null;
		}

		public KeyedItemInfo WithNewSiblingIndex(int newSiblingIndex)
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
		private readonly RenderBatchBuilder _owner;

		private readonly int _stamp;

		public static readonly ParameterViewLifetime Unbound;

		public ParameterViewLifetime(RenderBatchBuilder owner)
		{
			throw null;
		}

		public void AssertNotExpired()
		{
			throw null;
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
		public void OpenElement(int sequence, string elementName)
		{
			throw null;
		}

		public void CloseElement()
		{
			throw null;
		}

		public void AddMarkupContent(int sequence, string? markupContent)
		{
			throw null;
		}

		public void AddContent(int sequence, string? textContent)
		{
			throw null;
		}

		public void AddContent(int sequence, RenderFragment? fragment)
		{
			throw null;
		}

		public void AddContent<TValue>(int sequence, RenderFragment<TValue>? fragment, TValue value)
		{
			throw null;
		}

		public void AddContent(int sequence, MarkupString markupContent)
		{
			throw null;
		}

		public void AddContent(int sequence, object? textContent)
		{
			throw null;
		}

		public void AddAttribute(int sequence, string name)
		{
			throw null;
		}

		public void AddAttribute(int sequence, string name, bool value)
		{
			throw null;
		}

		public void AddAttribute(int sequence, string name, string? value)
		{
			throw null;
		}

		public void AddAttribute(int sequence, string name, MulticastDelegate? value)
		{
			throw null;
		}

		public void AddAttribute(int sequence, string name, EventCallback value)
		{
			throw null;
		}

		public void AddAttribute<TArgument>(int sequence, string name, EventCallback<TArgument> value)
		{
			throw null;
		}

		public void AddAttribute(int sequence, string name, object? value)
		{
			throw null;
		}

		public void AddAttribute(int sequence, RenderTreeFrame frame)
		{
			throw null;
		}

		public void AddMultipleAttributes(int sequence, IEnumerable<KeyValuePair<string, object>>? attributes)
		{
			throw null;
		}

		public void SetUpdatesAttributeName(string updatesAttributeName)
		{
			throw null;
		}

		public void OpenComponent<TComponent>(int sequence) where TComponent : notnull, IComponent
		{
			throw null;
		}

		public void OpenComponent(int sequence, Type componentType)
		{
			throw null;
		}

		public void SetKey(object? value)
		{
			throw null;
		}

		public void CloseComponent()
		{
			throw null;
		}

		public void AddElementReferenceCapture(int sequence, Action<ElementReference> elementReferenceCaptureAction)
		{
			throw null;
		}

		public void AddComponentReferenceCapture(int sequence, Action<object> componentReferenceCaptureAction)
		{
			throw null;
		}

		public void OpenRegion(int sequence)
		{
			throw null;
		}

		public void CloseRegion()
		{
			throw null;
		}

		public void Clear()
		{
			throw null;
		}

		internal void InsertAttributeExpensive(int insertAtIndex, int sequence, string attributeName, object? attributeValue)
		{
			throw null;
		}

		public ArrayRange<RenderTreeFrame> GetFrames()
		{
			throw null;
		}

		internal void AssertTreeIsValid(IComponent component)
		{
			throw null;
		}

		internal void ProcessDuplicateAttributes(int first)
		{
			throw null;
		}

		internal void TrackAttributeName(string name)
		{
			throw null;
		}

		void IDisposable.Dispose()
		{
			throw null;
		}

		public RenderTreeBuilder()
		{
			throw null;
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
		private readonly ArrayBuilder<T>? _builder;

		private readonly int _offset;

		private readonly int _count;

		public T[] Array
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

		internal ArrayBuilderSegment(ArrayBuilder<T> builder, int offset, int count)
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public EventFieldInfo()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.RenderTree\RenderBatch.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.RenderTree
{
	public readonly struct RenderBatch
	{
		public ArrayRange<RenderTreeDiff> UpdatedComponents
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

		internal RenderBatch(ArrayRange<RenderTreeDiff> updatedComponents, ArrayRange<RenderTreeFrame> referenceFrames, ArrayRange<int> disposedComponentIDs, ArrayRange<ulong> disposedEventHandlerIDs)
		{
			throw null;
		}
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
		[FieldOffset(0)]
		public readonly RenderTreeEditType Type;

		[FieldOffset(4)]
		public readonly int SiblingIndex;

		[FieldOffset(8)]
		public readonly int ReferenceFrameIndex;

		[FieldOffset(8)]
		public readonly int MoveToSiblingIndex;

		[FieldOffset(16)]
		public readonly string RemovedAttributeName;

		internal static RenderTreeEdit RemoveFrame(int siblingIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit PrependFrame(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit UpdateText(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit UpdateMarkup(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit SetAttribute(int siblingIndex, int referenceFrameIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit RemoveAttribute(int siblingIndex, string name)
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

		internal static RenderTreeEdit PermutationListEntry(int fromSiblingIndex, int toSiblingIndex)
		{
			throw null;
		}

		internal static RenderTreeEdit PermutationListEnd()
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
	public struct RenderTreeFrame
	{
		[FieldOffset(0)]
		internal int SequenceField;

		[FieldOffset(4)]
		internal RenderTreeFrameType FrameTypeField;

		[FieldOffset(8)]
		internal int ElementSubtreeLengthField;

		[FieldOffset(16)]
		internal string ElementNameField;

		[FieldOffset(24)]
		internal object ElementKeyField;

		[FieldOffset(16)]
		internal string TextContentField;

		[FieldOffset(8)]
		internal ulong AttributeEventHandlerIdField;

		[FieldOffset(16)]
		internal string AttributeNameField;

		[FieldOffset(24)]
		internal object AttributeValueField;

		[FieldOffset(32)]
		internal string AttributeEventUpdatesAttributeNameField;

		[FieldOffset(8)]
		internal int ComponentSubtreeLengthField;

		[FieldOffset(12)]
		internal int ComponentIdField;

		[FieldOffset(16)]
		internal Type ComponentTypeField;

		[FieldOffset(24)]
		internal ComponentState ComponentStateField;

		[FieldOffset(32)]
		internal object ComponentKeyField;

		[FieldOffset(8)]
		internal int RegionSubtreeLengthField;

		[FieldOffset(16)]
		internal string ElementReferenceCaptureIdField;

		[FieldOffset(24)]
		internal Action<ElementReference> ElementReferenceCaptureActionField;

		[FieldOffset(8)]
		internal int ComponentReferenceCaptureParentFrameIndexField;

		[FieldOffset(16)]
		internal Action<object> ComponentReferenceCaptureActionField;

		[FieldOffset(16)]
		internal string MarkupContentField;

		public int Sequence
		{
			get
			{
				throw null;
			}
		}

		public RenderTreeFrameType FrameType
		{
			get
			{
				throw null;
			}
		}

		public int ElementSubtreeLength
		{
			get
			{
				throw null;
			}
		}

		public string ElementName
		{
			get
			{
				throw null;
			}
		}

		public object ElementKey
		{
			get
			{
				throw null;
			}
		}

		public string TextContent
		{
			get
			{
				throw null;
			}
		}

		public ulong AttributeEventHandlerId
		{
			get
			{
				throw null;
			}
		}

		public string AttributeName
		{
			get
			{
				throw null;
			}
		}

		public object AttributeValue
		{
			get
			{
				throw null;
			}
		}

		public string AttributeEventUpdatesAttributeName
		{
			get
			{
				throw null;
			}
		}

		public int ComponentSubtreeLength
		{
			get
			{
				throw null;
			}
		}

		public int ComponentId
		{
			get
			{
				throw null;
			}
		}

		public Type ComponentType
		{
			get
			{
				throw null;
			}
		}

		internal ComponentState ComponentState
		{
			get
			{
				throw null;
			}
		}

		public object ComponentKey
		{
			get
			{
				throw null;
			}
		}

		public IComponent Component
		{
			get
			{
				throw null;
			}
		}

		public int RegionSubtreeLength
		{
			get
			{
				throw null;
			}
		}

		public string ElementReferenceCaptureId
		{
			get
			{
				throw null;
			}
		}

		public Action<ElementReference> ElementReferenceCaptureAction
		{
			get
			{
				throw null;
			}
		}

		public int ComponentReferenceCaptureParentFrameIndex
		{
			get
			{
				throw null;
			}
		}

		public Action<object> ComponentReferenceCaptureAction
		{
			get
			{
				throw null;
			}
		}

		public string MarkupContent
		{
			get
			{
				throw null;
			}
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

		public override string ToString()
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
		public string Location
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsNavigationIntercepted
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LocationChangedEventArgs(string location, bool isNavigationIntercepted)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\NavigationContext.cs
using System.Runtime.CompilerServices;
using System.Threading;

namespace Microsoft.AspNetCore.Components.Routing
{
	public sealed class NavigationContext
	{
		public string Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CancellationToken CancellationToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal NavigationContext(string path, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\RouteConstraint.cs
namespace Microsoft.AspNetCore.Components.Routing
{
	internal abstract class RouteConstraint
	{
		public abstract bool Match(string pathSegment, out object? convertedValue);

		public static RouteConstraint Parse(string template, string segment, string constraint)
		{
			throw null;
		}

		protected RouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components\Microsoft.AspNetCore.Components.Routing\Router.cs
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Routing
{
	public class Router : IComponent, IHandleAfterRender, IDisposable
	{
		private static class Log
		{
			internal static void DisplayingNotFound(ILogger logger, string path, string baseUri)
			{
				throw null;
			}

			internal static void NavigatingToComponent(ILogger logger, Type componentType, string path, string baseUri)
			{
				throw null;
			}

			internal static void NavigatingToExternalUri(ILogger logger, string externalUri, string path, string baseUri)
			{
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		[Parameter]
		public RenderFragment? Navigating
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public Func<NavigationContext, Task>? OnNavigateAsync
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public void Attach(RenderHandle renderHandle)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CSetParametersAsync_003Ed__52))]
		[DebuggerStepThrough]
		public Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}

		internal virtual void Refresh(bool isNavigationIntercepted)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CRunOnNavigateWithRefreshAsync_003Ed__58))]
		[DebuggerStepThrough]
		internal Task RunOnNavigateWithRefreshAsync(string path, bool isNavigationIntercepted)
		{
			throw null;
		}

		Task IHandleAfterRender.OnAfterRenderAsync()
		{
			throw null;
		}

		public Router()
		{
			throw null;
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
			throw null;
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public abstract class AuthenticationStateProvider
	{
		public event AuthenticationStateChangedHandler AuthenticationStateChanged
		{
			[CompilerGenerated]
			add
			{
				throw null;
			}
			[CompilerGenerated]
			remove
			{
				throw null;
			}
		}

		public abstract Task<AuthenticationState> GetAuthenticationStateAsync();

		protected void NotifyAuthenticationStateChanged(Task<AuthenticationState> task)
		{
			throw null;
		}

		protected AuthenticationStateProvider()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Authorization\Microsoft.AspNetCore.Components.Authorization\AuthorizeRouteView.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Rendering;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Authorization
{
	public sealed class AuthorizeRouteView : RouteView
	{
		private class AuthorizeRouteViewCore : AuthorizeViewCore
		{
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
					throw null;
				}
			}

			protected override IAuthorizeData[] GetAuthorizeData()
			{
				throw null;
			}

			public AuthorizeRouteViewCore()
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public AuthorizeRouteView()
		{
			throw null;
		}

		protected override void Render(RenderTreeBuilder builder)
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public AuthorizeView()
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003COnParametersSetAsync_003Ed__35))]
		[DebuggerStepThrough]
		protected override Task OnParametersSetAsync()
		{
			throw null;
		}

		protected abstract IAuthorizeData[] GetAuthorizeData();

		protected AuthorizeViewCore()
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
				throw null;
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder __builder)
		{
			throw null;
		}

		protected override void OnInitialized()
		{
			throw null;
		}

		void IDisposable.Dispose()
		{
			throw null;
		}

		public CascadingAuthenticationState()
		{
			throw null;
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
			throw null;
		}

		public DataAnnotationsValidator()
		{
			throw null;
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

		public event EventHandler<FieldChangedEventArgs>? OnFieldChanged
		{
			[CompilerGenerated]
			add
			{
				throw null;
			}
			[CompilerGenerated]
			remove
			{
				throw null;
			}
		}

		public event EventHandler<ValidationRequestedEventArgs>? OnValidationRequested
		{
			[CompilerGenerated]
			add
			{
				throw null;
			}
			[CompilerGenerated]
			remove
			{
				throw null;
			}
		}

		public event EventHandler<ValidationStateChangedEventArgs>? OnValidationStateChanged
		{
			[CompilerGenerated]
			add
			{
				throw null;
			}
			[CompilerGenerated]
			remove
			{
				throw null;
			}
		}

		public EditContext(object model)
		{
			throw null;
		}

		public FieldIdentifier Field(string fieldName)
		{
			throw null;
		}

		public void NotifyFieldChanged(in FieldIdentifier fieldIdentifier)
		{
			throw null;
		}

		public void NotifyValidationStateChanged()
		{
			throw null;
		}

		public void MarkAsUnmodified(in FieldIdentifier fieldIdentifier)
		{
			throw null;
		}

		public void MarkAsUnmodified()
		{
			throw null;
		}

		public bool IsModified()
		{
			throw null;
		}

		[IteratorStateMachine(typeof(_003CGetValidationMessages_003Ed__20))]
		public IEnumerable<string> GetValidationMessages()
		{
			throw null;
		}

		[IteratorStateMachine(typeof(_003CGetValidationMessages_003Ed__21))]
		public IEnumerable<string> GetValidationMessages(FieldIdentifier fieldIdentifier)
		{
			throw null;
		}

		public IEnumerable<string> GetValidationMessages(Expression<Func<object>> accessor)
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
			throw null;
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
		public object Model
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string FieldName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public static FieldIdentifier Create<TField>(Expression<Func<TField>> accessor)
		{
			throw null;
		}

		public FieldIdentifier(object model, string fieldName)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public bool Equals(FieldIdentifier otherIdentifier)
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
			throw null;
		}

		public void Add(in FieldIdentifier fieldIdentifier, string message)
		{
			throw null;
		}

		public void Add(Expression<Func<object>> accessor, string message)
		{
			throw null;
		}

		public void Add(in FieldIdentifier fieldIdentifier, IEnumerable<string> messages)
		{
			throw null;
		}

		public void Add(Expression<Func<object>> accessor, IEnumerable<string> messages)
		{
			throw null;
		}

		public void Clear()
		{
			throw null;
		}

		public void Clear(Expression<Func<object>> accessor)
		{
			throw null;
		}

		public void Clear(in FieldIdentifier fieldIdentifier)
		{
			throw null;
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
			throw null;
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
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\MessagePack\BufferWriter.cs
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace MessagePack
{
	internal ref struct BufferWriter
	{
		private IBufferWriter<byte> _output;

		private Span<byte> _span;

		private ArraySegment<byte> _segment;

		private int _buffered;

		private long _bytesCommitted;

		private SequencePool _sequencePool;

		private SequencePool.Rental _rental;

		public Span<byte> Span
		{
			get
			{
				throw null;
			}
		}

		public long BytesCommitted
		{
			get
			{
				throw null;
			}
		}

		internal IBufferWriter<byte> UnderlyingWriter
		{
			get
			{
				throw null;
			}
		}

		internal SequencePool.Rental SequenceRental
		{
			get
			{
				throw null;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public BufferWriter(IBufferWriter<byte> output)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal BufferWriter(SequencePool sequencePool, byte[] array)
		{
			throw null;
		}

		public Span<byte> GetSpan(int sizeHint)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref byte GetPointer(int sizeHint)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Commit()
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Advance(int count)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Write(ReadOnlySpan<byte> source)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Ensure(int count = 1)
		{
			throw null;
		}

		internal bool TryGetUncommittedSpan(out ReadOnlySpan<byte> span)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\MessagePack\ExtensionHeader.cs
using System;
using System.Runtime.CompilerServices;

namespace MessagePack
{
	internal struct ExtensionHeader : IEquatable<ExtensionHeader>
	{
		public sbyte TypeCode
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public uint Length
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public ExtensionHeader(sbyte typeCode, uint length)
		{
			throw null;
		}

		public ExtensionHeader(sbyte typeCode, int length)
		{
			throw null;
		}

		public bool Equals(ExtensionHeader other)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\MessagePack\ExtensionResult.cs
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace MessagePack
{
	internal struct ExtensionResult
	{
		public sbyte TypeCode
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public ReadOnlySequence<byte> Data
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public ExtensionHeader Header
		{
			get
			{
				throw null;
			}
		}

		public ExtensionResult(sbyte typeCode, Memory<byte> data)
		{
			throw null;
		}

		public ExtensionResult(sbyte typeCode, ReadOnlySequence<byte> data)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\MessagePack\MessagePackReader.cs
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Threading;

namespace MessagePack
{
	internal ref struct MessagePackReader
	{
		private SequenceReader<byte> reader;

		public CancellationToken CancellationToken
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public int Depth
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ReadOnlySequence<byte> Sequence
		{
			get
			{
				throw null;
			}
		}

		public SequencePosition Position
		{
			get
			{
				throw null;
			}
		}

		public long Consumed
		{
			get
			{
				throw null;
			}
		}

		public bool End
		{
			get
			{
				throw null;
			}
		}

		public bool IsNil
		{
			get
			{
				throw null;
			}
		}

		public MessagePackType NextMessagePackType
		{
			get
			{
				throw null;
			}
		}

		public byte NextCode
		{
			get
			{
				throw null;
			}
		}

		public MessagePackReader(ReadOnlyMemory<byte> memory)
		{
			throw null;
		}

		public MessagePackReader(in ReadOnlySequence<byte> readOnlySequence)
		{
			throw null;
		}

		public MessagePackReader Clone(in ReadOnlySequence<byte> readOnlySequence)
		{
			throw null;
		}

		public MessagePackReader CreatePeekReader()
		{
			throw null;
		}

		public void Skip()
		{
			throw null;
		}

		internal bool TrySkip()
		{
			throw null;
		}

		public Nil ReadNil()
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public bool TryReadNil()
		{
			throw null;
		}

		public ReadOnlySequence<byte> ReadRaw(long length)
		{
			throw null;
		}

		public ReadOnlySequence<byte> ReadRaw()
		{
			throw null;
		}

		public int ReadArrayHeader()
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public bool TryReadArrayHeader(out int count)
		{
			throw null;
		}

		public int ReadMapHeader()
		{
			throw null;
		}

		public bool TryReadMapHeader(out int count)
		{
			throw null;
		}

		public bool ReadBoolean()
		{
			throw null;
		}

		public char ReadChar()
		{
			throw null;
		}

		public float ReadSingle()
		{
			throw null;
		}

		public double ReadDouble()
		{
			throw null;
		}

		public DateTime ReadDateTime()
		{
			throw null;
		}

		public DateTime ReadDateTime(ExtensionHeader header)
		{
			throw null;
		}

		public ReadOnlySequence<byte>? ReadBytes()
		{
			throw null;
		}

		public ReadOnlySequence<byte>? ReadStringSequence()
		{
			throw null;
		}

		public bool TryReadStringSpan(out ReadOnlySpan<byte> span)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public string ReadString()
		{
			throw null;
		}

		public ExtensionHeader ReadExtensionFormatHeader()
		{
			throw null;
		}

		public bool TryReadExtensionFormatHeader(out ExtensionHeader extensionHeader)
		{
			throw null;
		}

		public ExtensionResult ReadExtensionFormat()
		{
			throw null;
		}

		public byte ReadByte()
		{
			throw null;
		}

		public ushort ReadUInt16()
		{
			throw null;
		}

		public uint ReadUInt32()
		{
			throw null;
		}

		public ulong ReadUInt64()
		{
			throw null;
		}

		public sbyte ReadSByte()
		{
			throw null;
		}

		public short ReadInt16()
		{
			throw null;
		}

		public int ReadInt32()
		{
			throw null;
		}

		public long ReadInt64()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\MessagePack\MessagePackType.cs
namespace MessagePack
{
	internal enum MessagePackType : byte
	{
		Unknown,
		Integer,
		Nil,
		Boolean,
		Float,
		String,
		Binary,
		Array,
		Map,
		Extension
	}
}


// Microsoft.AspNetCore.Components.Server\MessagePack\MessagePackWriter.cs
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Threading;

namespace MessagePack
{
	internal ref struct MessagePackWriter
	{
		private BufferWriter writer;

		public CancellationToken CancellationToken
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public bool OldSpec
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public MessagePackWriter(IBufferWriter<byte> writer)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		internal MessagePackWriter(SequencePool sequencePool, byte[] array)
		{
			throw null;
		}

		public MessagePackWriter Clone(IBufferWriter<byte> writer)
		{
			throw null;
		}

		public void Flush()
		{
			throw null;
		}

		public void WriteNil()
		{
			throw null;
		}

		public void WriteRaw(ReadOnlySpan<byte> rawMessagePackBlock)
		{
			throw null;
		}

		public void WriteRaw(in ReadOnlySequence<byte> rawMessagePackBlock)
		{
			throw null;
		}

		public void WriteArrayHeader(int count)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void WriteArrayHeader(uint count)
		{
			throw null;
		}

		public void WriteMapHeader(int count)
		{
			throw null;
		}

		public void WriteMapHeader(uint count)
		{
			throw null;
		}

		public void Write(byte value)
		{
			throw null;
		}

		public void WriteUInt8(byte value)
		{
			throw null;
		}

		public void Write(sbyte value)
		{
			throw null;
		}

		public void WriteInt8(sbyte value)
		{
			throw null;
		}

		public void Write(ushort value)
		{
			throw null;
		}

		public void WriteUInt16(ushort value)
		{
			throw null;
		}

		public void Write(short value)
		{
			throw null;
		}

		public void WriteInt16(short value)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Write(uint value)
		{
			throw null;
		}

		public void WriteUInt32(uint value)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Write(int value)
		{
			throw null;
		}

		public void WriteInt32(int value)
		{
			throw null;
		}

		public void Write(ulong value)
		{
			throw null;
		}

		public void WriteUInt64(ulong value)
		{
			throw null;
		}

		public void Write(long value)
		{
			throw null;
		}

		public void WriteInt64(long value)
		{
			throw null;
		}

		public void Write(bool value)
		{
			throw null;
		}

		public void Write(char value)
		{
			throw null;
		}

		public void Write(float value)
		{
			throw null;
		}

		public void Write(double value)
		{
			throw null;
		}

		public void Write(DateTime dateTime)
		{
			throw null;
		}

		public void Write(byte[] src)
		{
			throw null;
		}

		public void Write(ReadOnlySpan<byte> src)
		{
			throw null;
		}

		public void Write(in ReadOnlySequence<byte> src)
		{
			throw null;
		}

		public void WriteBinHeader(int length)
		{
			throw null;
		}

		public void WriteString(in ReadOnlySequence<byte> utf8stringBytes)
		{
			throw null;
		}

		public void WriteString(ReadOnlySpan<byte> utf8stringBytes)
		{
			throw null;
		}

		public void WriteStringHeader(int byteCount)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Write(string value)
		{
			throw null;
		}

		public void Write(ReadOnlySpan<char> value)
		{
			throw null;
		}

		public void WriteExtensionFormatHeader(ExtensionHeader extensionHeader)
		{
			throw null;
		}

		public void WriteExtensionFormat(ExtensionResult extensionData)
		{
			throw null;
		}

		public Span<byte> GetSpan(int length)
		{
			throw null;
		}

		public void Advance(int length)
		{
			throw null;
		}

		internal void WriteBigEndian(ushort value)
		{
			throw null;
		}

		internal void WriteBigEndian(uint value)
		{
			throw null;
		}

		internal void WriteBigEndian(ulong value)
		{
			throw null;
		}

		internal byte[] FlushAndGetArray()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\MessagePack\Nil.cs
using System;
using System.Runtime.InteropServices;

namespace MessagePack
{
	[StructLayout(LayoutKind.Sequential, Size = 1)]
	internal struct Nil : IEquatable<Nil>
	{
		public static readonly Nil Default;

		public override bool Equals(object obj)
		{
			throw null;
		}

		public bool Equals(Nil other)
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


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Builder\ComponentEndpointConventionBuilder.cs
using System;

namespace Microsoft.AspNetCore.Builder
{
	public sealed class ComponentEndpointConventionBuilder : IHubEndpointConventionBuilder, IEndpointConventionBuilder
	{
		internal ComponentEndpointConventionBuilder(IEndpointConventionBuilder hubEndpoint, IEndpointConventionBuilder disconnectEndpoint)
		{
			throw null;
		}

		public void Add(Action<EndpointBuilder> convention)
		{
			throw null;
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

		public static ComponentEndpointConventionBuilder MapBlazorHub(this IEndpointRouteBuilder endpoints, string path)
		{
			throw null;
		}

		public static ComponentEndpointConventionBuilder MapBlazorHub(this IEndpointRouteBuilder endpoints, Action<HttpConnectionDispatcherOptions> configureOptions)
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
		public string Name
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string TypeName
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string Assembly
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
		public int Sequence
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string AssemblyName
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string TypeName
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public IList<ComponentParameter> ParameterDefinitions
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public IList<object> ParameterValues
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public Guid InvocationId
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
		public const string ServerMarkerType = "server";

		public int? Sequence
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string Type
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string PrerenderId
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string Descriptor
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public static ServerComponentMarker Prerendered(int sequence, string descriptor)
		{
			throw null;
		}

		public static ServerComponentMarker NonPrerendered(int sequence, string descriptor)
		{
			throw null;
		}

		public ServerComponentMarker GetEndRecord()
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public CircuitOptions()
		{
			throw null;
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
			throw null;
		}

		protected abstract Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken);

		void IDisposable.Dispose()
		{
			throw null;
		}

		protected virtual void Dispose(bool disposing)
		{
			throw null;
		}
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
			throw null;
		}

		public ServerAuthenticationStateProvider()
		{
			throw null;
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

		internal Circuit(CircuitHost circuitHost)
		{
			throw null;
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

		public virtual Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task OnConnectionDownAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task OnCircuitClosedAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			throw null;
		}

		protected CircuitHandler()
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


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server.Circuits\ICircuitAccessor.cs
namespace Microsoft.AspNetCore.Components.Server.Circuits
{
	internal interface ICircuitAccessor
	{
		Circuit Circuit
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.Components.Server.Circuits\PendingRender.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Server.Circuits
{
	internal readonly struct PendingRender
	{
		public int ComponentId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RenderFragment RenderFragment
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public PendingRender(int componentId, RenderFragment renderFragment)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.AspNetCore.SignalR.Protocol\MessagePackHubProtocolWorker.cs
using MessagePack;
using System;
using System.Buffers;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	internal abstract class MessagePackHubProtocolWorker
	{
		public bool TryParseMessage(ref ReadOnlySequence<byte> input, IInvocationBinder binder, out HubMessage message)
		{
			throw null;
		}

		protected abstract object DeserializeObject(ref MessagePackReader reader, Type type, string field);

		public void WriteMessage(HubMessage message, IBufferWriter<byte> output)
		{
			throw null;
		}

		public ReadOnlyMemory<byte> GetMessageBytes(HubMessage message)
		{
			throw null;
		}

		protected abstract void Serialize(ref MessagePackWriter writer, Type type, object value);

		protected string ReadString(ref MessagePackReader reader, string field)
		{
			throw null;
		}

		protected MessagePackHubProtocolWorker()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\Microsoft.Extensions.DependencyInjection\ComponentServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Components.Server;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class ComponentServiceCollectionExtensions
	{
		private class DefaultServerSideBlazorBuilder : IServerSideBlazorBuilder
		{
			public IServiceCollection Services
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public DefaultServerSideBlazorBuilder(IServiceCollection services)
			{
				throw null;
			}
		}

		public static IServerSideBlazorBuilder AddServerSideBlazor(this IServiceCollection services, Action<CircuitOptions>? configure = null)
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
		private static readonly double TimestampToTicks;

		private long _startTimestamp;

		public bool IsActive
		{
			get
			{
				throw null;
			}
		}

		public static ValueStopwatch StartNew()
		{
			throw null;
		}

		public TimeSpan GetElapsedTime()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Server\System.Buffers\SequenceReader.cs
using System.Runtime.CompilerServices;

namespace System.Buffers
{
	internal ref struct SequenceReader<T> where T : unmanaged, IEquatable<T>
	{
		private bool usingSequence;

		private ReadOnlySequence<T> sequence;

		private SequencePosition currentPosition;

		private SequencePosition nextPosition;

		private ReadOnlyMemory<T> memory;

		private bool moreData;

		private long length;

		public bool End
		{
			get
			{
				throw null;
			}
		}

		public ReadOnlySequence<T> Sequence
		{
			get
			{
				throw null;
			}
		}

		public SequencePosition Position
		{
			get
			{
				throw null;
			}
		}

		public ReadOnlySpan<T> CurrentSpan
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public int CurrentSpanIndex
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public ReadOnlySpan<T> UnreadSpan
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				throw null;
			}
		}

		public long Consumed
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public long Remaining
		{
			get
			{
				throw null;
			}
		}

		public long Length
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				throw null;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public SequenceReader(in ReadOnlySequence<T> sequence)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public SequenceReader(ReadOnlyMemory<T> memory)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public bool TryPeek(out T value)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public bool TryRead(out T value)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Rewind(long count)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Advance(long count)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal void AdvanceCurrentSpan(long count)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal void AdvanceWithinSpan(long count)
		{
			throw null;
		}

		internal bool TryAdvance(long count)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public bool TryCopyTo(Span<T> destination)
		{
			throw null;
		}

		internal bool TryCopyMultisegment(Span<T> destination)
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
		public string? Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? Suffix
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? ValueAttribute
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? ChangeAttribute
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

		public string? Format
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public BindInputElementAttribute(string? type, string? suffix, string? valueAttribute, string? changeAttribute, bool isInvariantCulture, string? format)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components\ElementReferenceExtensions.cs
using Microsoft.JSInterop;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components
{
	public static class ElementReferenceExtensions
	{
		public static ValueTask FocusAsync(this ElementReference elementReference)
		{
			throw null;
		}

		internal static IJSRuntime GetJSRuntime(this ElementReference elementReference)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components\WebElementReferenceContext.cs
using Microsoft.JSInterop;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components
{
	public class WebElementReferenceContext : ElementReferenceContext
	{
		internal IJSRuntime JSRuntime
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public WebElementReferenceContext(IJSRuntime jsRuntime)
		{
			throw null;
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
		public static string FieldCssClass<TField>(this EditContext editContext, Expression<Func<TField>> accessor)
		{
			throw null;
		}

		public static string FieldCssClass(this EditContext editContext, in FieldIdentifier fieldIdentifier)
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
		public IReadOnlyDictionary<string, object>? AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public EditContext? EditContext
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		[Parameter]
		public object? Model
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public RenderFragment<EditContext>? ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public EditForm()
		{
			throw null;
		}

		protected override void OnParametersSet()
		{
			throw null;
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputBase.cs
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Forms
{
	public abstract class InputBase<TValue> : ComponentBase, IDisposable
	{
		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object>? AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public TValue Value
		{
			[CompilerGenerated]
			[return: MaybeNull]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			[param: AllowNull]
			set
			{
				throw null;
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
				throw null;
			}
		}

		[Parameter]
		public Expression<Func<TValue>>? ValueExpression
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public string? DisplayName
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		protected internal FieldIdentifier FieldIdentifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected TValue CurrentValue
		{
			[return: MaybeNull]
			get
			{
				throw null;
			}
			[param: AllowNull]
			set
			{
				throw null;
			}
		}

		protected string? CurrentValueAsString
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			set
			{
				throw null;
			}
		}

		protected string CssClass
		{
			get
			{
				throw null;
			}
		}

		protected InputBase()
		{
			throw null;
		}

		protected virtual string? FormatValueAsString([AllowNull] TValue value)
		{
			throw null;
		}

		protected abstract bool TryParseValueFromString(string? value, [MaybeNull] out TValue result, [NotNullWhen(false)] out string? validationErrorMessage);

		public override Task SetParametersAsync(ParameterView parameters)
		{
			throw null;
		}

		protected virtual void Dispose(bool disposing)
		{
			throw null;
		}

		void IDisposable.Dispose()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputCheckbox.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputCheckbox : InputBase<bool>
	{
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string? value, out bool result, [NotNullWhen(false)] out string? validationErrorMessage)
		{
			throw null;
		}

		public InputCheckbox()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputDate.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics.CodeAnalysis;
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
				throw null;
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected override string FormatValueAsString([AllowNull] TValue value)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string? value, [MaybeNull] out TValue result, [NotNullWhen(false)] out string? validationErrorMessage)
		{
			throw null;
		}

		public InputDate()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputNumber.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics.CodeAnalysis;
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
				throw null;
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string? value, [MaybeNull] out TValue result, [NotNullWhen(false)] out string? validationErrorMessage)
		{
			throw null;
		}

		protected override string? FormatValueAsString([AllowNull] TValue value)
		{
			throw null;
		}

		public InputNumber()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputRadio.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputRadio<TValue> : ComponentBase
	{
		internal InputRadioContext? Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object>? AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public TValue Value
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			[return: MaybeNull]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			[param: AllowNull]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public string? Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected override void OnParametersSet()
		{
			throw null;
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		public InputRadio()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputRadioGroup.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputRadioGroup<TValue> : InputBase<TValue>
	{
		[Parameter]
		public RenderFragment? ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public string? Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected override void OnParametersSet()
		{
			throw null;
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string? value, [MaybeNull] out TValue result, [NotNullWhen(false)] out string? validationErrorMessage)
		{
			throw null;
		}

		public InputRadioGroup()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputSelect.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputSelect<TValue> : InputBase<TValue>
	{
		[Parameter]
		public RenderFragment? ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string? value, [MaybeNull] out TValue result, [NotNullWhen(false)] out string? validationErrorMessage)
		{
			throw null;
		}

		public InputSelect()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputText.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputText : InputBase<string>
	{
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string? value, out string? result, [NotNullWhen(false)] out string? validationErrorMessage)
		{
			throw null;
		}

		public InputText()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Forms\InputTextArea.cs
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Components.Forms
{
	public class InputTextArea : InputBase<string>
	{
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected override bool TryParseValueFromString(string? value, out string? result, [NotNullWhen(false)] out string? validationErrorMessage)
		{
			throw null;
		}

		public InputTextArea()
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
		public IReadOnlyDictionary<string, object>? AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public Expression<Func<TValue>>? For
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ValidationMessage()
		{
			throw null;
		}

		protected override void OnParametersSet()
		{
			throw null;
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected virtual void Dispose(bool disposing)
		{
			throw null;
		}

		void IDisposable.Dispose()
		{
			throw null;
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
		[Parameter]
		public object? Model
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object>? AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ValidationSummary()
		{
			throw null;
		}

		protected override void OnParametersSet()
		{
			throw null;
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		protected virtual void Dispose(bool disposing)
		{
			throw null;
		}

		void IDisposable.Dispose()
		{
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public EventFieldInfo? EventFieldInfo
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public WebEventDescriptor()
		{
			throw null;
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
		public string? ActiveClass
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter(CaptureUnmatchedValues = true)]
		public IReadOnlyDictionary<string, object>? AdditionalAttributes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected string? CssClass
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public RenderFragment? ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		protected override void OnInitialized()
		{
			throw null;
		}

		protected override void OnParametersSet()
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		public NavLink()
		{
			throw null;
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
	[BindInputElement(null, null, "value", "onchange", false, null)]
	[BindInputElement(null, "value", "value", "onchange", false, null)]
	[BindInputElement("checkbox", null, "checked", "onchange", false, null)]
	[BindInputElement("text", null, "value", "onchange", false, null)]
	[BindInputElement("number", null, "value", "onchange", true, null)]
	[BindInputElement("number", "value", "value", "onchange", true, null)]
	[BindInputElement("date", null, "value", "onchange", true, "yyyy-MM-dd")]
	[BindInputElement("date", "value", "value", "onchange", true, "yyyy-MM-dd")]
	[BindInputElement("datetime-local", null, "value", "onchange", true, "yyyy-MM-ddTHH:mm:ss")]
	[BindInputElement("datetime-local", "value", "value", "onchange", true, "yyyy-MM-ddTHH:mm:ss")]
	[BindInputElement("month", null, "value", "onchange", true, "yyyy-MM")]
	[BindInputElement("month", "value", "value", "onchange", true, "yyyy-MM")]
	[BindInputElement("time", null, "value", "onchange", true, "HH:mm:ss")]
	[BindInputElement("time", "value", "value", "onchange", true, "HH:mm:ss")]
	[BindElement("select", null, "value", "onchange")]
	[BindElement("textarea", null, "value", "onchange")]
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
				throw null;
			}
		}

		public ClipboardEventArgs()
		{
			throw null;
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
				throw null;
			}
		}

		public string? EffectAllowed
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public DataTransfer()
		{
			throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public DataTransferItem()
		{
			throw null;
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
				throw null;
			}
		}

		public DragEventArgs()
		{
			throw null;
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
		public string? Message
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? Filename
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public string? Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ErrorEventArgs()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\EventHandlers.cs
using System;

namespace Microsoft.AspNetCore.Components.Web
{
	[EventHandler("onfocus", typeof(FocusEventArgs), true, true)]
	[EventHandler("onblur", typeof(FocusEventArgs), true, true)]
	[EventHandler("onfocusin", typeof(FocusEventArgs), true, true)]
	[EventHandler("onfocusout", typeof(FocusEventArgs), true, true)]
	[EventHandler("onmouseover", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmouseout", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmousemove", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmousedown", typeof(MouseEventArgs), true, true)]
	[EventHandler("onmouseup", typeof(MouseEventArgs), true, true)]
	[EventHandler("onclick", typeof(MouseEventArgs), true, true)]
	[EventHandler("ondblclick", typeof(MouseEventArgs), true, true)]
	[EventHandler("onwheel", typeof(WheelEventArgs), true, true)]
	[EventHandler("onmousewheel", typeof(WheelEventArgs), true, true)]
	[EventHandler("oncontextmenu", typeof(MouseEventArgs), true, true)]
	[EventHandler("ondrag", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragend", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragenter", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragleave", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragover", typeof(DragEventArgs), true, true)]
	[EventHandler("ondragstart", typeof(DragEventArgs), true, true)]
	[EventHandler("ondrop", typeof(DragEventArgs), true, true)]
	[EventHandler("onkeydown", typeof(KeyboardEventArgs), true, true)]
	[EventHandler("onkeyup", typeof(KeyboardEventArgs), true, true)]
	[EventHandler("onkeypress", typeof(KeyboardEventArgs), true, true)]
	[EventHandler("onchange", typeof(ChangeEventArgs), true, true)]
	[EventHandler("oninput", typeof(ChangeEventArgs), true, true)]
	[EventHandler("oninvalid", typeof(EventArgs), true, true)]
	[EventHandler("onreset", typeof(EventArgs), true, true)]
	[EventHandler("onselect", typeof(EventArgs), true, true)]
	[EventHandler("onselectstart", typeof(EventArgs), true, true)]
	[EventHandler("onselectionchange", typeof(EventArgs), true, true)]
	[EventHandler("onsubmit", typeof(EventArgs), true, true)]
	[EventHandler("onbeforecopy", typeof(EventArgs), true, true)]
	[EventHandler("onbeforecut", typeof(EventArgs), true, true)]
	[EventHandler("onbeforepaste", typeof(EventArgs), true, true)]
	[EventHandler("oncopy", typeof(ClipboardEventArgs), true, true)]
	[EventHandler("oncut", typeof(ClipboardEventArgs), true, true)]
	[EventHandler("onpaste", typeof(ClipboardEventArgs), true, true)]
	[EventHandler("ontouchcancel", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchend", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchmove", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchstart", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchenter", typeof(TouchEventArgs), true, true)]
	[EventHandler("ontouchleave", typeof(TouchEventArgs), true, true)]
	[EventHandler("ongotpointercapture", typeof(PointerEventArgs), true, true)]
	[EventHandler("onlostpointercapture", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointercancel", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerdown", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerenter", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerleave", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointermove", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerout", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerover", typeof(PointerEventArgs), true, true)]
	[EventHandler("onpointerup", typeof(PointerEventArgs), true, true)]
	[EventHandler("oncanplay", typeof(EventArgs), true, true)]
	[EventHandler("oncanplaythrough", typeof(EventArgs), true, true)]
	[EventHandler("oncuechange", typeof(EventArgs), true, true)]
	[EventHandler("ondurationchange", typeof(EventArgs), true, true)]
	[EventHandler("onemptied", typeof(EventArgs), true, true)]
	[EventHandler("onpause", typeof(EventArgs), true, true)]
	[EventHandler("onplay", typeof(EventArgs), true, true)]
	[EventHandler("onplaying", typeof(EventArgs), true, true)]
	[EventHandler("onratechange", typeof(EventArgs), true, true)]
	[EventHandler("onseeked", typeof(EventArgs), true, true)]
	[EventHandler("onseeking", typeof(EventArgs), true, true)]
	[EventHandler("onstalled", typeof(EventArgs), true, true)]
	[EventHandler("onstop", typeof(EventArgs), true, true)]
	[EventHandler("onsuspend", typeof(EventArgs), true, true)]
	[EventHandler("ontimeupdate", typeof(EventArgs), true, true)]
	[EventHandler("onvolumechange", typeof(EventArgs), true, true)]
	[EventHandler("onwaiting", typeof(EventArgs), true, true)]
	[EventHandler("onloadstart", typeof(ProgressEventArgs), true, true)]
	[EventHandler("ontimeout", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onabort", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onload", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onloadend", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onprogress", typeof(ProgressEventArgs), true, true)]
	[EventHandler("onerror", typeof(ErrorEventArgs), true, true)]
	[EventHandler("onactivate", typeof(EventArgs), true, true)]
	[EventHandler("onbeforeactivate", typeof(EventArgs), true, true)]
	[EventHandler("onbeforedeactivate", typeof(EventArgs), true, true)]
	[EventHandler("ondeactivate", typeof(EventArgs), true, true)]
	[EventHandler("onended", typeof(EventArgs), true, true)]
	[EventHandler("onfullscreenchange", typeof(EventArgs), true, true)]
	[EventHandler("onfullscreenerror", typeof(EventArgs), true, true)]
	[EventHandler("onloadeddata", typeof(EventArgs), true, true)]
	[EventHandler("onloadedmetadata", typeof(EventArgs), true, true)]
	[EventHandler("onpointerlockchange", typeof(EventArgs), true, true)]
	[EventHandler("onpointerlockerror", typeof(EventArgs), true, true)]
	[EventHandler("onreadystatechange", typeof(EventArgs), true, true)]
	[EventHandler("onscroll", typeof(EventArgs), true, true)]
	[EventHandler("ontoggle", typeof(EventArgs), true, true)]
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
		public string? Type
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public FocusEventArgs()
		{
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public KeyboardEventArgs()
		{
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public double OffsetX
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public double OffsetY
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public MouseEventArgs()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\PointerEventArgs.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class PointerEventArgs : MouseEventArgs
	{
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public PointerEventArgs()
		{
			throw null;
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
				throw null;
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
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ProgressEventArgs()
		{
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public TouchEventArgs()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\TouchPoint.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class TouchPoint
	{
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public TouchPoint()
		{
			throw null;
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

		public static EventCallback<ClipboardEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ClipboardEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<DragEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<DragEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<DragEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<DragEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<ErrorEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<ErrorEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<ErrorEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ErrorEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<FocusEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<FocusEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<FocusEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<FocusEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<KeyboardEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<KeyboardEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<KeyboardEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<KeyboardEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<MouseEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<MouseEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<MouseEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<MouseEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<PointerEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<PointerEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<PointerEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<PointerEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<ProgressEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<ProgressEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<ProgressEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<ProgressEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<TouchEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<TouchEventArgs> callback)
		{
			throw null;
		}

		public static EventCallback<TouchEventArgs> Create(this EventCallbackFactory factory, object receiver, Func<TouchEventArgs, Task> callback)
		{
			throw null;
		}

		public static EventCallback<WheelEventArgs> Create(this EventCallbackFactory factory, object receiver, Action<WheelEventArgs> callback)
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
			throw null;
		}

		public static void AddEventStopPropagationAttribute(this RenderTreeBuilder builder, int sequence, string eventName, bool value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web\WheelEventArgs.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web
{
	public class WheelEventArgs : MouseEventArgs
	{
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public WheelEventArgs()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web.Virtualization\ItemsProviderDelegate.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Web.Virtualization
{
	public delegate ValueTask<ItemsProviderResult<TItem>> ItemsProviderDelegate<TItem>(ItemsProviderRequest request);
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web.Virtualization\ItemsProviderRequest.cs
using System.Runtime.CompilerServices;
using System.Threading;

namespace Microsoft.AspNetCore.Components.Web.Virtualization
{
	public readonly struct ItemsProviderRequest
	{
		public int StartIndex
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int Count
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CancellationToken CancellationToken
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ItemsProviderRequest(int startIndex, int count, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web.Virtualization\ItemsProviderResult.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web.Virtualization
{
	public readonly struct ItemsProviderResult<TItem>
	{
		public IEnumerable<TItem> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int TotalItemCount
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ItemsProviderResult(IEnumerable<TItem> items, int totalItemCount)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web.Virtualization\IVirtualizeJsCallbacks.cs
namespace Microsoft.AspNetCore.Components.Web.Virtualization
{
	internal interface IVirtualizeJsCallbacks
	{
		void OnBeforeSpacerVisible(float spacerSize, float containerSize);

		void OnAfterSpacerVisible(float spacerSize, float containerSize);
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web.Virtualization\PlaceholderContext.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Components.Web.Virtualization
{
	public readonly struct PlaceholderContext
	{
		public int Index
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public PlaceholderContext(int index)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Components.Web\Microsoft.AspNetCore.Components.Web.Virtualization\Virtualize.cs
using Microsoft.AspNetCore.Components.Rendering;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Components.Web.Virtualization
{
	public sealed class Virtualize<TItem> : ComponentBase, IVirtualizeJsCallbacks, IAsyncDisposable
	{
		[Parameter]
		public RenderFragment<TItem>? ChildContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public RenderFragment<TItem>? ItemContent
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public RenderFragment<PlaceholderContext>? Placeholder
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public float ItemSize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public ItemsProviderDelegate<TItem>? ItemsProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Parameter]
		public ICollection<TItem>? Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected override void OnParametersSet()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(Virtualize<>._003COnAfterRenderAsync_003Ed__42))]
		[DebuggerStepThrough]
		protected override Task OnAfterRenderAsync(bool firstRender)
		{
			throw null;
		}

		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			throw null;
		}

		void IVirtualizeJsCallbacks.OnBeforeSpacerVisible(float spacerSize, float containerSize)
		{
			throw null;
		}

		void IVirtualizeJsCallbacks.OnAfterSpacerVisible(float spacerSize, float containerSize)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(Virtualize<>._003CDisposeAsync_003Ed__52))]
		[DebuggerStepThrough]
		public ValueTask DisposeAsync()
		{
			throw null;
		}

		public Virtualize()
		{
			throw null;
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
			throw null;
		}

		public AddressInUseException(string message, Exception inner)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\BaseConnectionContext.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public abstract class BaseConnectionContext : IAsyncDisposable
	{
		public abstract string ConnectionId
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			get;
			[System.Runtime.CompilerServices.NullableContext(1)]
			set;
		}

		public abstract IFeatureCollection Features
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			get;
		}

		public abstract IDictionary<object, object?> Items
		{
			get;
			set;
		}

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
				throw null;
			}
		}

		public virtual EndPoint? LocalEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public virtual EndPoint? RemoteEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public abstract void Abort();

		public abstract void Abort(ConnectionAbortedException abortReason);

		public virtual ValueTask DisposeAsync()
		{
			throw null;
		}

		protected BaseConnectionContext()
		{
			throw null;
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
			throw null;
		}

		public ConnectionAbortedException(string message)
		{
			throw null;
		}

		public ConnectionAbortedException(string message, Exception inner)
		{
			throw null;
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
			throw null;
		}

		public IConnectionBuilder Use(Func<ConnectionDelegate, ConnectionDelegate> middleware)
		{
			throw null;
		}

		public ConnectionDelegate Build()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionBuilderExtensions.cs
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public static class ConnectionBuilderExtensions
	{
		public static IConnectionBuilder UseConnectionHandler<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TConnectionHandler>(this IConnectionBuilder connectionBuilder) where TConnectionHandler : ConnectionHandler
		{
			throw null;
		}

		public static IConnectionBuilder Use(this IConnectionBuilder connectionBuilder, Func<ConnectionContext, Func<Task>, Task> middleware)
		{
			throw null;
		}

		public static IConnectionBuilder Run(this IConnectionBuilder connectionBuilder, Func<ConnectionContext, Task> middleware)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionContext.cs
using System;
using System.IO.Pipelines;

namespace Microsoft.AspNetCore.Connections
{
	public abstract class ConnectionContext : BaseConnectionContext, IAsyncDisposable
	{
		public abstract IDuplexPipe Transport
		{
			get;
			set;
		}

		public override void Abort(ConnectionAbortedException abortReason)
		{
			throw null;
		}

		public override void Abort()
		{
			throw null;
		}

		protected ConnectionContext()
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

		protected ConnectionHandler()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\ConnectionItems.cs
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Connections
{
	public class ConnectionItems : IDictionary<object, object?>, ICollection<KeyValuePair<object, object?>>, IEnumerable<KeyValuePair<object, object?>>, IEnumerable
	{
		public IDictionary<object, object?> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		object? IDictionary<object, object>.this[object key]
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		ICollection<object> IDictionary<object, object>.Keys
		{
			get
			{
				throw null;
			}
		}

		ICollection<object?> IDictionary<object, object>.Values
		{
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

		public ConnectionItems()
		{
			throw null;
		}

		public ConnectionItems(IDictionary<object, object?> items)
		{
			throw null;
		}

		void IDictionary<object, object>.Add(object key, object? value)
		{
			throw null;
		}

		bool IDictionary<object, object>.ContainsKey(object key)
		{
			throw null;
		}

		bool IDictionary<object, object>.Remove(object key)
		{
			throw null;
		}

		bool IDictionary<object, object>.TryGetValue(object key, out object? value)
		{
			throw null;
		}

		void ICollection<KeyValuePair<object, object>>.Add(KeyValuePair<object, object?> item)
		{
			throw null;
		}

		void ICollection<KeyValuePair<object, object>>.Clear()
		{
			throw null;
		}

		bool ICollection<KeyValuePair<object, object>>.Contains(KeyValuePair<object, object?> item)
		{
			throw null;
		}

		void ICollection<KeyValuePair<object, object>>.CopyTo(KeyValuePair<object, object?>[] array, int arrayIndex)
		{
			throw null;
		}

		bool ICollection<KeyValuePair<object, object>>.Remove(KeyValuePair<object, object?> item)
		{
			throw null;
		}

		IEnumerator<KeyValuePair<object, object?>> IEnumerable<KeyValuePair<object, object>>.GetEnumerator()
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
			throw null;
		}

		public ConnectionResetException(string message, Exception inner)
		{
			throw null;
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
	public class DefaultConnectionContext : ConnectionContext, IConnectionIdFeature, IConnectionItemsFeature, IConnectionTransportFeature, IConnectionUserFeature, IConnectionLifetimeFeature, IConnectionEndPointFeature
	{
		public override string ConnectionId
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public override IFeatureCollection Features
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ClaimsPrincipal? User
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public override IDictionary<object, object?> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public IDuplexPipe? Application
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public override IDuplexPipe Transport
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public override EndPoint? LocalEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public override EndPoint? RemoteEndPoint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public DefaultConnectionContext()
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public DefaultConnectionContext(string id)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public DefaultConnectionContext(string id, IDuplexPipe transport, IDuplexPipe application)
		{
			throw null;
		}

		public override void Abort(ConnectionAbortedException abortReason)
		{
			throw null;
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
			throw null;
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

		IConnectionBuilder Use(Func<ConnectionDelegate, ConnectionDelegate> middleware);

		ConnectionDelegate Build();
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


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IMultiplexedConnectionBuilder.cs
using System;

namespace Microsoft.AspNetCore.Connections
{
	public interface IMultiplexedConnectionBuilder
	{
		IServiceProvider ApplicationServices
		{
			get;
		}

		IMultiplexedConnectionBuilder Use(Func<MultiplexedConnectionDelegate, MultiplexedConnectionDelegate> middleware);

		MultiplexedConnectionDelegate Build();
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IMultiplexedConnectionFactory.cs
using Microsoft.AspNetCore.Http.Features;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public interface IMultiplexedConnectionFactory
	{
		ValueTask<MultiplexedConnectionContext> ConnectAsync(EndPoint endpoint, IFeatureCollection? features = null, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IMultiplexedConnectionListener.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public interface IMultiplexedConnectionListener : IAsyncDisposable
	{
		EndPoint EndPoint
		{
			get;
		}

		ValueTask UnbindAsync(CancellationToken cancellationToken = default(CancellationToken));

		ValueTask<MultiplexedConnectionContext> AcceptAsync(IFeatureCollection? features = null, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\IMultiplexedConnectionListenerFactory.cs
using Microsoft.AspNetCore.Http.Features;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public interface IMultiplexedConnectionListenerFactory
	{
		ValueTask<IMultiplexedConnectionListener> BindAsync(EndPoint endpoint, IFeatureCollection? features = null, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\MultiplexedConnectionBuilder.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Connections
{
	public class MultiplexedConnectionBuilder : IMultiplexedConnectionBuilder
	{
		public IServiceProvider ApplicationServices
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MultiplexedConnectionBuilder(IServiceProvider applicationServices)
		{
			throw null;
		}

		public IMultiplexedConnectionBuilder Use(Func<MultiplexedConnectionDelegate, MultiplexedConnectionDelegate> middleware)
		{
			throw null;
		}

		public MultiplexedConnectionDelegate Build()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\MultiplexedConnectionContext.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public abstract class MultiplexedConnectionContext : BaseConnectionContext, IAsyncDisposable
	{
		public abstract ValueTask<ConnectionContext> AcceptAsync(CancellationToken cancellationToken = default(CancellationToken));

		public abstract ValueTask<ConnectionContext> ConnectAsync(IFeatureCollection? features = null, CancellationToken cancellationToken = default(CancellationToken));

		protected MultiplexedConnectionContext()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections\MultiplexedConnectionDelegate.cs
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Connections
{
	public delegate Task MultiplexedConnectionDelegate(MultiplexedConnectionContext connection);
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
			throw null;
		}

		public override string ToString()
		{
			throw null;
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
		EndPoint? LocalEndPoint
		{
			get;
			set;
		}

		EndPoint? RemoteEndPoint
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
		IDictionary<object, object?> Items
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
		ClaimsPrincipal? User
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


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IProtocolErrorCodeFeature.cs
namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IProtocolErrorCodeFeature
	{
		long Error
		{
			get;
			set;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IStreamDirectionFeature.cs
namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IStreamDirectionFeature
	{
		bool CanRead
		{
			get;
		}

		bool CanWrite
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\IStreamIdFeature.cs
namespace Microsoft.AspNetCore.Connections.Features
{
	public interface IStreamIdFeature
	{
		long StreamId
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
		SslProtocols Protocol
		{
			get;
		}

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
	}
}


// Microsoft.AspNetCore.Connections.Abstractions\Microsoft.AspNetCore.Connections.Features\ITransferFormatFeature.cs
namespace Microsoft.AspNetCore.Connections.Features
{
	public interface ITransferFormatFeature
	{
		TransferFormat SupportedFormats
		{
			get;
		}

		TransferFormat ActiveFormat
		{
			get;
			set;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public CookiePolicyOptions()
		{
			throw null;
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

		public CookieOptions CookieOptions
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

		public bool HasConsent
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
				throw null;
			}
		}

		public AppendCookieContext(HttpContext context, CookieOptions options, string name, string value)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.CookiePolicy\Microsoft.AspNetCore.CookiePolicy\CookiePolicyMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.CookiePolicy
{
	public class CookiePolicyMiddleware
	{
		private class CookiesWrapperFeature : IResponseCookiesFeature
		{
			public IResponseCookies Cookies
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public CookiesWrapperFeature(ResponseCookiesWrapper wrapper)
			{
				throw null;
			}
		}

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
				throw null;
			}
		}

		public CookiePolicyMiddleware(RequestDelegate next, IOptions<CookiePolicyOptions> options, ILoggerFactory factory)
		{
			throw null;
		}

		public CookiePolicyMiddleware(RequestDelegate next, IOptions<CookiePolicyOptions> options)
		{
			throw null;
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

		public CookieOptions CookieOptions
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

		public bool HasConsent
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
				throw null;
			}
		}

		public DeleteCookieContext(HttpContext context, CookieOptions options, string name)
		{
			throw null;
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


// Microsoft.AspNetCore.CookiePolicy\Microsoft.Extensions.DependencyInjection\CookiePolicyServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Builder;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class CookiePolicyServiceCollectionExtensions
	{
		public static IServiceCollection AddCookiePolicy(this IServiceCollection services, Action<CookiePolicyOptions> configureOptions)
		{
			throw null;
		}

		public static IServiceCollection AddCookiePolicy<TService>(this IServiceCollection services, Action<CookiePolicyOptions, TService> configureOptions) where TService : class
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Builder\CorsEndpointConventionBuilderExtensions.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;

namespace Microsoft.AspNetCore.Builder
{
	public static class CorsEndpointConventionBuilderExtensions
	{
		public static TBuilder RequireCors<TBuilder>(this TBuilder builder, string policyName) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder RequireCors<TBuilder>(this TBuilder builder, Action<CorsPolicyBuilder> configurePolicy) where TBuilder : IEndpointConventionBuilder
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

		public static IApplicationBuilder UseCors(this IApplicationBuilder app, string policyName)
		{
			throw null;
		}

		public static IApplicationBuilder UseCors(this IApplicationBuilder app, Action<CorsPolicyBuilder> configurePolicy)
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
	public class CorsPolicyMetadata : ICorsPolicyMetadata, ICorsMetadata
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
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors\DisableCorsAttribute.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;

namespace Microsoft.AspNetCore.Cors
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
	public class DisableCorsAttribute : Attribute, IDisableCorsAttribute, ICorsMetadata
	{
		public DisableCorsAttribute()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors\EnableCorsAttribute.cs
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Cors
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
	public class EnableCorsAttribute : Attribute, IEnableCorsAttribute, ICorsMetadata
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
				throw null;
			}
		}

		public EnableCorsAttribute()
		{
			throw null;
		}

		public EnableCorsAttribute(string policyName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsConstants.cs
namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public static class CorsConstants
	{
		public static readonly string PreflightHttpMethod;

		public static readonly string Origin;

		public static readonly string AnyOrigin;

		public static readonly string AccessControlRequestMethod;

		public static readonly string AccessControlRequestHeaders;

		public static readonly string AccessControlAllowOrigin;

		public static readonly string AccessControlAllowHeaders;

		public static readonly string AccessControlExposeHeaders;

		public static readonly string AccessControlAllowMethods;

		public static readonly string AccessControlAllowCredentials;

		public static readonly string AccessControlMaxAge;
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
		public CorsMiddleware(RequestDelegate next, ICorsService corsService, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public CorsMiddleware(RequestDelegate next, ICorsService corsService, ILoggerFactory loggerFactory, string policyName)
		{
			throw null;
		}

		public CorsMiddleware(RequestDelegate next, ICorsService corsService, CorsPolicy policy, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public Task Invoke(HttpContext context, ICorsPolicyProvider corsPolicyProvider)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Cors\Microsoft.AspNetCore.Cors.Infrastructure\CorsOptions.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
	public class CorsOptions
	{
		internal IDictionary<string, (CorsPolicy policy, Task<CorsPolicy> policyTask)> PolicyMap
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string DefaultPolicyName
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public void AddDefaultPolicy(CorsPolicy policy)
		{
			throw null;
		}

		public void AddDefaultPolicy(Action<CorsPolicyBuilder> configurePolicy)
		{
			throw null;
		}

		public void AddPolicy(string name, CorsPolicy policy)
		{
			throw null;
		}

		public void AddPolicy(string name, Action<CorsPolicyBuilder> configurePolicy)
		{
			throw null;
		}

		public CorsPolicy GetPolicy(string name)
		{
			throw null;
		}

		public CorsOptions()
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
				throw null;
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
				throw null;
			}
		}

		public CorsPolicy()
		{
			throw null;
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
		public CorsPolicyBuilder(params string[] origins)
		{
			throw null;
		}

		public CorsPolicyBuilder(CorsPolicy policy)
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

		public CorsPolicyBuilder WithHeaders(params string[] headers)
		{
			throw null;
		}

		public CorsPolicyBuilder WithExposedHeaders(params string[] exposedHeaders)
		{
			throw null;
		}

		public CorsPolicyBuilder WithMethods(params string[] methods)
		{
			throw null;
		}

		public CorsPolicyBuilder AllowCredentials()
		{
			throw null;
		}

		public CorsPolicyBuilder DisallowCredentials()
		{
			throw null;
		}

		public CorsPolicyBuilder AllowAnyOrigin()
		{
			throw null;
		}

		public CorsPolicyBuilder AllowAnyMethod()
		{
			throw null;
		}

		public CorsPolicyBuilder AllowAnyHeader()
		{
			throw null;
		}

		public CorsPolicyBuilder SetPreflightMaxAge(TimeSpan preflightMaxAge)
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

		public CorsPolicy Build()
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
				throw null;
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
				throw null;
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

		public IList<string> AllowedHeaders
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<string> AllowedExposedHeaders
		{
			[CompilerGenerated]
			get
			{
				throw null;
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
				throw null;
			}
		}

		public override string ToString()
		{
			throw null;
		}

		public CorsResult()
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
			throw null;
		}

		public CorsResult EvaluatePolicy(HttpContext context, string policyName)
		{
			throw null;
		}

		public CorsResult EvaluatePolicy(HttpContext context, CorsPolicy policy)
		{
			throw null;
		}

		public virtual void EvaluateRequest(HttpContext context, CorsPolicy policy, CorsResult result)
		{
			throw null;
		}

		public virtual void EvaluatePreflightRequest(HttpContext context, CorsPolicy policy, CorsResult result)
		{
			throw null;
		}

		public virtual void ApplyResult(CorsResult result, HttpResponse response)
		{
			throw null;
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
			throw null;
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
		CorsResult EvaluatePolicy(HttpContext context, CorsPolicy policy);

		void ApplyResult(CorsResult result, HttpResponse response);
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
		private const int BCRYPTBUFFER_VERSION = 0;

		public uint ulVersion;

		public uint cBuffers;

		public unsafe BCryptBuffer* pBuffers;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Initialize(ref BCryptBufferDesc bufferDesc)
		{
			throw null;
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
			throw null;
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
		{
			throw null;
		}

		protected unsafe uint GetProperty(string pszProperty, void* pbOutput, uint cbOutput)
		{
			throw null;
		}

		protected unsafe void SetProperty(string pszProperty, void* pbInput, uint cbInput)
		{
			throw null;
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
		public static IDataProtectionBuilder SetApplicationName(this IDataProtectionBuilder builder, string applicationName)
		{
			throw null;
		}

		public static IDataProtectionBuilder AddKeyEscrowSink(this IDataProtectionBuilder builder, IKeyEscrowSink sink)
		{
			throw null;
		}

		public static IDataProtectionBuilder AddKeyEscrowSink<TImplementation>(this IDataProtectionBuilder builder) where TImplementation : class, IKeyEscrowSink
		{
			throw null;
		}

		public static IDataProtectionBuilder AddKeyEscrowSink(this IDataProtectionBuilder builder, Func<IServiceProvider, IKeyEscrowSink> factory)
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

		public static IDataProtectionBuilder UnprotectKeysWithAnyCertificate(this IDataProtectionBuilder builder, params X509Certificate2[] certificates)
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

		public static IDataProtectionBuilder SetDefaultKeyLifetime(this IDataProtectionBuilder builder, TimeSpan lifetime)
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
				throw null;
			}
		}

		public DataProtectionOptions()
		{
			throw null;
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
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement.Internal;
using Microsoft.Extensions.Logging;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection
{
	public sealed class EphemeralDataProtectionProvider : IDataProtectionProvider
	{
		private sealed class EphemeralKeyRing<T> : IKeyRing, IKeyRingProvider where T : AlgorithmConfiguration, new()
		{
			public IAuthenticatedEncryptor DefaultAuthenticatedEncryptor
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public Guid DefaultKeyId
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public EphemeralKeyRing(ILoggerFactory loggerFactory)
			{
				throw null;
			}

			public IAuthenticatedEncryptor GetAuthenticatedEncryptorByKeyId(Guid keyId, out bool isRevoked)
			{
				throw null;
			}

			public IKeyRing GetCurrentKeyRing()
			{
				throw null;
			}
		}

		public EphemeralDataProtectionProvider()
		{
			throw null;
		}

		public EphemeralDataProtectionProvider(ILoggerFactory loggerFactory)
		{
			throw null;
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
	public interface IPersistedDataProtector : IDataProtector, IDataProtectionProvider
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
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection
{
	public sealed class Secret : IDisposable, ISecret
	{
		public int Length
		{
			get
			{
				throw null;
			}
		}

		public Secret(ArraySegment<byte> value)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public Secret(byte[] value)
		{
			throw null;
		}

		public unsafe Secret(byte* secret, int secretLength)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public Secret(ISecret secret)
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}

		public static Secret Random(int numBytes)
		{
			throw null;
		}

		public void WriteSecretIntoBuffer(ArraySegment<byte> buffer)
		{
			throw null;
		}

		public unsafe void WriteSecretIntoBuffer(byte* buffer, int bufferLength)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\AuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class AuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		public AuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}

		internal IAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret, AuthenticatedEncryptorConfiguration authenticatedConfiguration)
		{
			throw null;
		}

		internal static bool IsGcmAlgorithm(EncryptionAlgorithm algorithm)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\CngCbcAuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Cng;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class CngCbcAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		public CngCbcAuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}

		internal CbcAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret, CngCbcAuthenticatedEncryptorConfiguration configuration)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption\CngGcmAuthenticatedEncryptorFactory.cs
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Cng;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class CngGcmAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		public CngGcmAuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}

		internal GcmAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret, CngGcmAuthenticatedEncryptorConfiguration configuration)
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
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Managed;
using Microsoft.Extensions.Logging;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
	public sealed class ManagedAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
	{
		private static class AlgorithmActivator
		{
			private interface IActivator<out T>
			{
				Func<T> Creator
				{
					get;
				}
			}

			private class AlgorithmActivatorCore<T> : IActivator<T> where T : new()
			{
				public Func<T> Creator
				{
					[CompilerGenerated]
					get
					{
						throw null;
					}
				}

				public AlgorithmActivatorCore()
				{
					throw null;
				}
			}

			public static Func<T> CreateFactory<T>(Type implementation)
			{
				throw null;
			}
		}

		public ManagedAuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
		{
			throw null;
		}

		internal ManagedAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(ISecret secret, ManagedAuthenticatedEncryptorConfiguration configuration)
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
		internal const int KDK_SIZE_IN_BYTES = 64;

		public abstract IAuthenticatedEncryptorDescriptor CreateNewDescriptor();

		protected AlgorithmConfiguration()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\AuthenticatedEncryptorConfiguration.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class AuthenticatedEncryptorConfiguration : AlgorithmConfiguration, IInternalAlgorithmConfiguration
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
				throw null;
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
				throw null;
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}

		IAuthenticatedEncryptorDescriptor IInternalAlgorithmConfiguration.CreateDescriptorFromSecret(ISecret secret)
		{
			throw null;
		}

		void IInternalAlgorithmConfiguration.Validate()
		{
			throw null;
		}

		public AuthenticatedEncryptorConfiguration()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\AuthenticatedEncryptorDescriptor.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class AuthenticatedEncryptorDescriptor : IAuthenticatedEncryptorDescriptor
	{
		internal ISecret MasterKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal AuthenticatedEncryptorConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AuthenticatedEncryptorDescriptor(AuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
			throw null;
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

		public AuthenticatedEncryptorDescriptorDeserializer()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngCbcAuthenticatedEncryptorConfiguration.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngCbcAuthenticatedEncryptorConfiguration : AlgorithmConfiguration, IInternalAlgorithmConfiguration
	{
		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}

		IAuthenticatedEncryptorDescriptor IInternalAlgorithmConfiguration.CreateDescriptorFromSecret(ISecret secret)
		{
			throw null;
		}

		void IInternalAlgorithmConfiguration.Validate()
		{
			throw null;
		}

		public CngCbcAuthenticatedEncryptorConfiguration()
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
		internal ISecret MasterKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal CngCbcAuthenticatedEncryptorConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CngCbcAuthenticatedEncryptorDescriptor(CngCbcAuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
			throw null;
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

		public CngCbcAuthenticatedEncryptorDescriptorDeserializer()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\CngGcmAuthenticatedEncryptorConfiguration.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class CngGcmAuthenticatedEncryptorConfiguration : AlgorithmConfiguration, IInternalAlgorithmConfiguration
	{
		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}

		IAuthenticatedEncryptorDescriptor IInternalAlgorithmConfiguration.CreateDescriptorFromSecret(ISecret secret)
		{
			throw null;
		}

		void IInternalAlgorithmConfiguration.Validate()
		{
			throw null;
		}

		public CngGcmAuthenticatedEncryptorConfiguration()
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
		internal ISecret MasterKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal CngGcmAuthenticatedEncryptorConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CngGcmAuthenticatedEncryptorDescriptor(CngGcmAuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
			throw null;
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

		public CngGcmAuthenticatedEncryptorDescriptorDeserializer()
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


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\IInternalAlgorithmConfiguration.cs
namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	internal interface IInternalAlgorithmConfiguration
	{
		IAuthenticatedEncryptorDescriptor CreateDescriptorFromSecret(ISecret secret);

		void Validate();
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel\ManagedAuthenticatedEncryptorConfiguration.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
	public sealed class ManagedAuthenticatedEncryptorConfiguration : AlgorithmConfiguration, IInternalAlgorithmConfiguration
	{
		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		[ApplyPolicy]
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
				throw null;
			}
		}

		public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
		{
			throw null;
		}

		IAuthenticatedEncryptorDescriptor IInternalAlgorithmConfiguration.CreateDescriptorFromSecret(ISecret secret)
		{
			throw null;
		}

		void IInternalAlgorithmConfiguration.Validate()
		{
			throw null;
		}

		public ManagedAuthenticatedEncryptorConfiguration()
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
		internal ISecret MasterKey
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal ManagedAuthenticatedEncryptorConfiguration Configuration
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ManagedAuthenticatedEncryptorDescriptor(ManagedAuthenticatedEncryptorConfiguration configuration, ISecret masterKey)
		{
			throw null;
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

		public ManagedAuthenticatedEncryptorDescriptorDeserializer()
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
		internal static bool IsMarkedAsRequiringEncryption(this XElement element)
		{
			throw null;
		}

		public static void MarkAsRequiresEncryption(this XElement element)
		{
			throw null;
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
			throw null;
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
	internal abstract class CngAuthenticatedEncryptorBase : IOptimizedAuthenticatedEncryptor, IAuthenticatedEncryptor, IDisposable
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

		protected CngAuthenticatedEncryptorBase()
		{
			throw null;
		}
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

		IAuthenticatedEncryptorDescriptor Descriptor
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

		void RevokeKey(Guid keyId, string reason = null);

		void RevokeAllKeys(DateTimeOffset revocationDate, string reason = null);
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

		public IAuthenticatedEncryptorDescriptor Descriptor
		{
			get
			{
				throw null;
			}
		}

		public KeyBase(Guid keyId, DateTimeOffset creationDate, DateTimeOffset activationDate, DateTimeOffset expirationDate, Lazy<IAuthenticatedEncryptorDescriptor> lazyDescriptor, IEnumerable<IAuthenticatedEncryptorFactory> encryptorFactories)
		{
			throw null;
		}

		public IAuthenticatedEncryptor CreateEncryptor()
		{
			throw null;
		}

		internal void SetRevoked()
		{
			throw null;
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
				throw null;
			}
		}

		internal TimeSpan KeyPropagationWindow
		{
			get
			{
				throw null;
			}
		}

		internal TimeSpan KeyRingRefreshPeriod
		{
			get
			{
				throw null;
			}
		}

		internal TimeSpan MaxServerClockSkew
		{
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
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

		public KeyManagementOptions()
		{
			throw null;
		}

		internal KeyManagementOptions(KeyManagementOptions other)
		{
			throw null;
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
		private sealed class AggregateKeyEscrowSink : IKeyEscrowSink
		{
			public AggregateKeyEscrowSink(IList<IKeyEscrowSink> sinks)
			{
				throw null;
			}

			public void Store(Guid keyId, XElement element)
			{
				throw null;
			}
		}

		internal static readonly XName KeyElementName;

		internal static readonly XName IdAttributeName;

		internal static readonly XName VersionAttributeName;

		internal static readonly XName CreationDateElementName;

		internal static readonly XName ActivationDateElementName;

		internal static readonly XName ExpirationDateElementName;

		internal static readonly XName DescriptorElementName;

		internal static readonly XName DeserializerTypeAttributeName;

		internal static readonly XName RevocationElementName;

		internal static readonly XName RevocationDateElementName;

		internal static readonly XName ReasonElementName;

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
			throw null;
		}

		public XmlKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		internal XmlKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator, ILoggerFactory loggerFactory, IDefaultKeyStorageDirectories keyStorageDirectories)
		{
			throw null;
		}

		internal XmlKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator, ILoggerFactory loggerFactory, IInternalXmlKeyManager internalXmlKeyManager)
		{
			throw null;
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

		public void RevokeAllKeys(DateTimeOffset revocationDate, string reason = null)
		{
			throw null;
		}

		public void RevokeKey(Guid keyId, string reason = null)
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
			throw null;
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

		internal CacheableKeyRing(CancellationToken expirationToken, DateTimeOffset expirationTime, IKey defaultKey, IEnumerable<IKey> allKeys)
		{
			throw null;
		}

		internal CacheableKeyRing(CancellationToken expirationToken, DateTimeOffset expirationTime, IKeyRing keyRing)
		{
			throw null;
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
			throw null;
		}

		public virtual IReadOnlyCollection<XElement> GetAllElements()
		{
			throw null;
		}

		public virtual void StoreElement(XElement element, string friendlyName)
		{
			throw null;
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
			throw null;
		}

		public virtual IReadOnlyCollection<XElement> GetAllElements()
		{
			throw null;
		}

		public virtual void StoreElement(XElement element, string friendlyName)
		{
			throw null;
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

		public CertificateResolver()
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
	public sealed class CertificateXmlEncryptor : IInternalCertificateXmlEncryptor, IXmlEncryptor
	{
		public CertificateXmlEncryptor(string thumbprint, ICertificateResolver certificateResolver, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public CertificateXmlEncryptor(X509Certificate2 certificate, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		internal CertificateXmlEncryptor(ILoggerFactory loggerFactory, IInternalCertificateXmlEncryptor encryptor)
		{
			throw null;
		}

		public EncryptedXmlInfo Encrypt(XElement plaintextElement)
		{
			throw null;
		}

		EncryptedData IInternalCertificateXmlEncryptor.PerformEncryption(EncryptedXml encryptedXml, XmlElement elementToEncrypt)
		{
			throw null;
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
			throw null;
		}

		public DpapiNGXmlDecryptor(IServiceProvider services)
		{
			throw null;
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
			throw null;
		}

		public EncryptedXmlInfo Encrypt(XElement plaintextElement)
		{
			throw null;
		}

		internal static string GetDefaultProtectionDescriptorString()
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
			throw null;
		}

		public DpapiXmlDecryptor(IServiceProvider services)
		{
			throw null;
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
			throw null;
		}

		public EncryptedXmlInfo Encrypt(XElement plaintextElement)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection\Microsoft.AspNetCore.DataProtection.XmlEncryption\EncryptedXmlDecryptor.cs
using System;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
	public sealed class EncryptedXmlDecryptor : IInternalEncryptedXmlDecryptor, IXmlDecryptor
	{
		private class EncryptedXmlWithCertificateKeys : EncryptedXml
		{
			public EncryptedXmlWithCertificateKeys(XmlKeyDecryptionOptions options, XmlDocument document)
			{
				throw null;
			}

			public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
			{
				throw null;
			}
		}

		public EncryptedXmlDecryptor()
		{
			throw null;
		}

		public EncryptedXmlDecryptor(IServiceProvider services)
		{
			throw null;
		}

		public XElement Decrypt(XElement encryptedElement)
		{
			throw null;
		}

		void IInternalEncryptedXmlDecryptor.PerformPreDecryptionSetup(EncryptedXml encryptedXml)
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
			throw null;
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

		public NullXmlDecryptor()
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
			throw null;
		}

		public NullXmlEncryptor(IServiceProvider services)
		{
			throw null;
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
		private sealed class TimeLimitedWrappingProtector : IDataProtector, IDataProtectionProvider
		{
			public DateTimeOffset Expiration;

			public TimeLimitedWrappingProtector(ITimeLimitedDataProtector innerProtector)
			{
				throw null;
			}

			public IDataProtector CreateProtector(string purpose)
			{
				throw null;
			}

			public byte[] Protect(byte[] plaintext)
			{
				throw null;
			}

			public byte[] Unprotect(byte[] protectedData)
			{
				throw null;
			}
		}

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
		public static IDataProtectionProvider Create(string applicationName)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory, Action<IDataProtectionBuilder> setupAction)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(string applicationName, X509Certificate2 certificate)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory, X509Certificate2 certificate)
		{
			throw null;
		}

		public static IDataProtectionProvider Create(DirectoryInfo keyDirectory, Action<IDataProtectionBuilder> setupAction, X509Certificate2 certificate)
		{
			throw null;
		}

		internal static IDataProtectionProvider CreateProvider(DirectoryInfo? keyDirectory, Action<IDataProtectionBuilder> setupAction, X509Certificate2? certificate)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.DataProtection.Extensions\Microsoft.AspNetCore.DataProtection\ITimeLimitedDataProtector.cs
using System;

namespace Microsoft.AspNetCore.DataProtection
{
	public interface ITimeLimitedDataProtector : IDataProtector, IDataProtectionProvider
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public DeveloperExceptionPageOptions()
		{
			throw null;
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

		public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app, string errorHandlingPath)
		{
			throw null;
		}

		public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app, Action<IApplicationBuilder> configure)
		{
			throw null;
		}

		public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app, ExceptionHandlerOptions options)
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public ExceptionHandlerOptions()
		{
			throw null;
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
		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app, StatusCodePagesOptions options)
		{
			throw null;
		}

		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app)
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

		public static IApplicationBuilder UseStatusCodePages(this IApplicationBuilder app, Action<IApplicationBuilder> configuration)
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
				throw null;
			}
		}

		public StatusCodePagesOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Builder\WelcomePageExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Builder
{
	public static class WelcomePageExtensions
	{
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

		public static IApplicationBuilder UseWelcomePage(this IApplicationBuilder app)
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
				throw null;
			}
		}

		public WelcomePageOptions()
		{
			throw null;
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class DeveloperExceptionPageMiddleware
	{
		public DeveloperExceptionPageMiddleware(RequestDelegate next, IOptions<DeveloperExceptionPageOptions> options, ILoggerFactory loggerFactory, IWebHostEnvironment hostingEnvironment, DiagnosticSource diagnosticSource, IEnumerable<IDeveloperPageExceptionFilter> filters)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__9))]
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
	public class ExceptionHandlerFeature : IExceptionHandlerPathFeature, IExceptionHandlerFeature
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
				throw null;
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
				throw null;
			}
		}

		public ExceptionHandlerFeature()
		{
			throw null;
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
			throw null;
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

		public StatusCodePagesOptions Options
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

		public StatusCodeContext(HttpContext context, StatusCodePagesOptions options, RequestDelegate next)
		{
			throw null;
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
				throw null;
			}
		}

		public StatusCodePagesFeature()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.Diagnostics\StatusCodePagesMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class StatusCodePagesMiddleware
	{
		public StatusCodePagesMiddleware(RequestDelegate next, IOptions<StatusCodePagesOptions> options)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__3))]
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public StatusCodeReExecuteFeature()
		{
			throw null;
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
			throw null;
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.AspNetCore.DiagnosticsViewPage.Views\BaseView.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.DiagnosticsViewPage.Views
{
	internal abstract class BaseView
	{
		protected HttpContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HttpRequest Request
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HttpResponse Response
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected StreamWriter Output
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HtmlEncoder HtmlEncoder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected JavaScriptEncoder JavaScriptEncoder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[AsyncStateMachine(typeof(_003CExecuteAsync_003Ed__28))]
		[DebuggerStepThrough]
		public Task ExecuteAsync(HttpContext context)
		{
			throw null;
		}

		public abstract Task ExecuteAsync();

		protected void WriteLiteral(string value)
		{
			throw null;
		}

		protected void WriteLiteral(object value)
		{
			throw null;
		}

		protected void WriteAttributeValue(string thingy, int startPostion, object value, int endValue, int dealyo, bool yesno)
		{
			throw null;
		}

		protected void BeginWriteAttribute(string name, string beginning, int startPosition, string ending, int endPosition, int thingy)
		{
			throw null;
		}

		protected void EndWriteAttribute()
		{
			throw null;
		}

		protected void WriteAttributeTo(TextWriter writer, string name, string leader, string trailer, params AttributeValue[] values)
		{
			throw null;
		}

		protected void Write(object value)
		{
			throw null;
		}

		protected void Write(string value)
		{
			throw null;
		}

		protected void Write(HelperResult result)
		{
			throw null;
		}

		protected void WriteTo(TextWriter writer, object value)
		{
			throw null;
		}

		protected void WriteTo(TextWriter writer, string value)
		{
			throw null;
		}

		protected void WriteLiteralTo(TextWriter writer, object value)
		{
			throw null;
		}

		protected void WriteLiteralTo(TextWriter writer, string value)
		{
			throw null;
		}

		protected string HtmlEncodeAndReplaceLineBreaks(string input)
		{
			throw null;
		}

		protected BaseView()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.Extensions.DependencyInjection\ExceptionHandlerServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Builder;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class ExceptionHandlerServiceCollectionExtensions
	{
		public static IServiceCollection AddExceptionHandler(this IServiceCollection services, Action<ExceptionHandlerOptions> configureOptions)
		{
			throw null;
		}

		public static IServiceCollection AddExceptionHandler<TService>(this IServiceCollection services, Action<ExceptionHandlerOptions, TService> configureOptions) where TService : class
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics\Microsoft.Extensions.RazorViews\BaseView.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.Extensions.RazorViews
{
	internal abstract class BaseView
	{
		protected HttpContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HttpRequest Request
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HttpResponse Response
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected TextWriter Output
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HtmlEncoder HtmlEncoder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected JavaScriptEncoder JavaScriptEncoder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[AsyncStateMachine(typeof(_003CExecuteAsync_003Ed__31))]
		[DebuggerStepThrough]
		public Task ExecuteAsync(Stream stream)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CExecuteAsync_003Ed__32))]
		[DebuggerStepThrough]
		public Task ExecuteAsync(HttpContext context)
		{
			throw null;
		}

		public abstract Task ExecuteAsync();

		protected virtual void PushWriter(TextWriter writer)
		{
			throw null;
		}

		protected virtual TextWriter PopWriter()
		{
			throw null;
		}

		protected void WriteLiteral(object value)
		{
			throw null;
		}

		protected void WriteLiteral(string value)
		{
			throw null;
		}

		protected void WriteAttributeValue(string thingy, int startPostion, object value, int endValue, int dealyo, bool yesno)
		{
			throw null;
		}

		protected void BeginWriteAttribute(string name, string beginning, int startPosition, string ending, int endPosition, int thingy)
		{
			throw null;
		}

		protected void EndWriteAttribute()
		{
			throw null;
		}

		protected void WriteAttribute(string name, string leader, string trailer, params AttributeValue[] values)
		{
			throw null;
		}

		protected void Write(HelperResult result)
		{
			throw null;
		}

		protected void Write(object value)
		{
			throw null;
		}

		protected void Write(string value)
		{
			throw null;
		}

		protected string HtmlEncodeAndReplaceLineBreaks(string input)
		{
			throw null;
		}

		protected BaseView()
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
		public string SourceFilePath
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

		public string CompiledContent
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

		public string FailureSummary
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CompilationFailure(string sourceFilePath, string sourceFileContent, string compiledContent, IEnumerable<DiagnosticMessage> messages)
		{
			throw null;
		}

		public CompilationFailure(string sourceFilePath, string sourceFileContent, string compiledContent, IEnumerable<DiagnosticMessage> messages, string failureSummary)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Diagnostics.Abstractions\Microsoft.AspNetCore.Diagnostics\DiagnosticMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Diagnostics
{
	public class DiagnosticMessage
	{
		public string SourceFilePath
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

		public int StartLine
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

		public int EndLine
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int EndColumn
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

		public DiagnosticMessage(string message, string formattedMessage, string filePath, int startLine, int startColumn, int endLine, int endColumn)
		{
			throw null;
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
		public HttpContext HttpContext
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

		public ErrorContext(HttpContext httpContext, Exception exception)
		{
			throw null;
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
		string OriginalPathBase
		{
			get;
			set;
		}

		string OriginalPath
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

		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path, string port)
		{
			throw null;
		}

		public static IApplicationBuilder UseHealthChecks(this IApplicationBuilder app, PathString path, int port, HealthCheckOptions options)
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Diagnostics.HealthChecks
{
	public class HealthCheckMiddleware
	{
		public HealthCheckMiddleware(RequestDelegate next, IOptions<HealthCheckOptions> healthCheckOptions, HealthCheckService healthCheckService)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvokeAsync_003Ed__4))]
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public HealthCheckOptions()
		{
			throw null;
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
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public HostFilteringOptions()
		{
			throw null;
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
		{
			throw null;
		}

		public override void Configure(IApplicationBuilder app)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting\ISupportsStartup.cs
using Microsoft.AspNetCore.Builder;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Hosting
{
	internal interface ISupportsStartup
	{
		IWebHostBuilder Configure(Action<WebHostBuilderContext, IApplicationBuilder> configure);

		IWebHostBuilder UseStartup([DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] Type startupType);

		IWebHostBuilder UseStartup<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] TStartup>(Func<WebHostBuilderContext, TStartup> startupFactory);
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

		IServiceProvider IStartup.ConfigureServices(IServiceCollection services)
		{
			throw null;
		}

		public virtual void ConfigureServices(IServiceCollection services)
		{
			throw null;
		}

		public virtual IServiceProvider CreateServiceProvider(IServiceCollection services)
		{
			throw null;
		}

		protected StartupBase()
		{
			throw null;
		}
	}
	public abstract class StartupBase<TBuilder> : StartupBase
	{
		public StartupBase(IServiceProviderFactory<TBuilder> factory)
		{
			throw null;
		}

		public override IServiceProvider CreateServiceProvider(IServiceCollection services)
		{
			throw null;
		}

		public virtual void ConfigureContainer(TBuilder builder)
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
			throw null;
		}

		public string GetSetting(string key)
		{
			throw null;
		}

		public IWebHostBuilder UseSetting(string key, string? value)
		{
			throw null;
		}

		public IWebHostBuilder ConfigureServices(Action<IServiceCollection> configureServices)
		{
			throw null;
		}

		public IWebHostBuilder ConfigureServices(Action<WebHostBuilderContext, IServiceCollection> configureServices)
		{
			throw null;
		}

		public IWebHostBuilder ConfigureAppConfiguration(Action<WebHostBuilderContext, IConfigurationBuilder> configureDelegate)
		{
			throw null;
		}

		public IWebHost Build()
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
using System.Diagnostics.CodeAnalysis;

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

		public static IWebHostBuilder UseStartup<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] TStartup>(this IWebHostBuilder hostBuilder, Func<WebHostBuilderContext, TStartup> startupFactory) where TStartup : class
		{
			throw null;
		}

		public static IWebHostBuilder UseStartup(this IWebHostBuilder hostBuilder, [DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] Type startupType)
		{
			throw null;
		}

		public static IWebHostBuilder UseStartup<[DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] TStartup>(this IWebHostBuilder hostBuilder) where TStartup : class
		{
			throw null;
		}

		public static IWebHostBuilder UseDefaultServiceProvider(this IWebHostBuilder hostBuilder, Action<ServiceProviderOptions> configure)
		{
			throw null;
		}

		public static IWebHostBuilder UseDefaultServiceProvider(this IWebHostBuilder hostBuilder, Action<WebHostBuilderContext, ServiceProviderOptions> configure)
		{
			throw null;
		}

		public static IWebHostBuilder ConfigureAppConfiguration(this IWebHostBuilder hostBuilder, Action<IConfigurationBuilder> configureDelegate)
		{
			throw null;
		}

		public static IWebHostBuilder ConfigureLogging(this IWebHostBuilder hostBuilder, Action<ILoggingBuilder> configureLogging)
		{
			throw null;
		}

		public static IWebHostBuilder ConfigureLogging(this IWebHostBuilder hostBuilder, Action<WebHostBuilderContext, ILoggingBuilder> configureLogging)
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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Hosting
{
	public static class WebHostExtensions
	{
		[AsyncStateMachine(typeof(_003CStopAsync_003Ed__0))]
		[DebuggerStepThrough]
		public static Task StopAsync(this IWebHost host, TimeSpan timeout)
		{
			throw null;
		}

		public static void WaitForShutdown(this IWebHost host)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CWaitForShutdownAsync_003Ed__2))]
		[DebuggerStepThrough]
		public static Task WaitForShutdownAsync(this IWebHost host, CancellationToken token = default(CancellationToken))
		{
			throw null;
		}

		public static void Run(this IWebHost host)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CRunAsync_003Ed__4))]
		[DebuggerStepThrough]
		public static Task RunAsync(this IWebHost host, CancellationToken token = default(CancellationToken))
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
			throw null;
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
				throw null;
			}
		}

		public ServerAddressesFeature()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Hosting.StaticWebAssets\StaticWebAssetsLoader.cs
using Microsoft.Extensions.Configuration;
using System.IO;

namespace Microsoft.AspNetCore.Hosting.StaticWebAssets
{
	public class StaticWebAssetsLoader
	{
		internal const string StaticWebAssetsManifestName = "Microsoft.AspNetCore.StaticWebAssets.xml";

		public static void UseStaticWebAssets(IWebHostEnvironment environment, IConfiguration configuration)
		{
			throw null;
		}

		internal static void UseStaticWebAssetsCore(IWebHostEnvironment environment, Stream manifest)
		{
			throw null;
		}

		internal static Stream? ResolveManifest(IWebHostEnvironment environment, IConfiguration configuration)
		{
			throw null;
		}

		public StaticWebAssetsLoader()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting\Microsoft.AspNetCore.Http\DefaultHttpContextFactory.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class DefaultHttpContextFactory : IHttpContextFactory
	{
		internal IHttpContextAccessor? HttpContextAccessor
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
		}

		public DefaultHttpContextFactory(IServiceProvider serviceProvider)
		{
			throw null;
		}

		public HttpContext Create(IFeatureCollection featureCollection)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal void Initialize(DefaultHttpContext httpContext, IFeatureCollection featureCollection)
		{
			throw null;
		}

		public void Dispose(HttpContext httpContext)
		{
			throw null;
		}

		internal void Dispose(DefaultHttpContext httpContext)
		{
			throw null;
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


// Microsoft.AspNetCore.Hosting\Microsoft.Extensions.RazorViews\BaseView.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.Extensions.RazorViews
{
	internal abstract class BaseView
	{
		protected HttpContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HttpRequest Request
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HttpResponse Response
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected TextWriter Output
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HtmlEncoder HtmlEncoder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		protected JavaScriptEncoder JavaScriptEncoder
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[AsyncStateMachine(typeof(_003CExecuteAsync_003Ed__31))]
		[DebuggerStepThrough]
		public Task ExecuteAsync(Stream stream)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CExecuteAsync_003Ed__32))]
		[DebuggerStepThrough]
		public Task ExecuteAsync(HttpContext context)
		{
			throw null;
		}

		public abstract Task ExecuteAsync();

		protected virtual void PushWriter(TextWriter writer)
		{
			throw null;
		}

		protected virtual TextWriter PopWriter()
		{
			throw null;
		}

		protected void WriteLiteral(object value)
		{
			throw null;
		}

		protected void WriteLiteral(string value)
		{
			throw null;
		}

		protected void WriteAttributeValue(string thingy, int startPostion, object value, int endValue, int dealyo, bool yesno)
		{
			throw null;
		}

		protected void BeginWriteAttribute(string name, string beginning, int startPosition, string ending, int endPosition, int thingy)
		{
			throw null;
		}

		protected void EndWriteAttribute()
		{
			throw null;
		}

		protected void WriteAttribute(string name, string leader, string trailer, params AttributeValue[] values)
		{
			throw null;
		}

		protected void Write(HelperResult result)
		{
			throw null;
		}

		protected void Write(object value)
		{
			throw null;
		}

		protected void Write(string value)
		{
			throw null;
		}

		protected string HtmlEncodeAndReplaceLineBreaks(string input)
		{
			throw null;
		}

		protected BaseView()
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

		public static readonly string Staging;

		public static readonly string Production;
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\HostingAbstractionsWebHostBuilderExtensions.cs
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.Configuration;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Hosting
{
	public static class HostingAbstractionsWebHostBuilderExtensions
	{
		public static IWebHostBuilder UseConfiguration(this IWebHostBuilder hostBuilder, IConfiguration configuration)
		{
			throw null;
		}

		public static IWebHostBuilder CaptureStartupErrors(this IWebHostBuilder hostBuilder, bool captureStartupErrors)
		{
			throw null;
		}

		[RequiresUnreferencedCode("Types and members the loaded assembly depends on might be removed.")]
		public static IWebHostBuilder UseStartup(this IWebHostBuilder hostBuilder, string startupAssemblyName)
		{
			throw null;
		}

		public static IWebHostBuilder UseServer(this IWebHostBuilder hostBuilder, IServer server)
		{
			throw null;
		}

		public static IWebHostBuilder UseEnvironment(this IWebHostBuilder hostBuilder, string environment)
		{
			throw null;
		}

		public static IWebHostBuilder UseContentRoot(this IWebHostBuilder hostBuilder, string contentRoot)
		{
			throw null;
		}

		public static IWebHostBuilder UseWebRoot(this IWebHostBuilder hostBuilder, string webRoot)
		{
			throw null;
		}

		public static IWebHostBuilder UseUrls(this IWebHostBuilder hostBuilder, params string[] urls)
		{
			throw null;
		}

		public static IWebHostBuilder PreferHostingUrls(this IWebHostBuilder hostBuilder, bool preferHostingUrls)
		{
			throw null;
		}

		public static IWebHostBuilder SuppressStatusMessages(this IWebHostBuilder hostBuilder, bool suppressStatusMessages)
		{
			throw null;
		}

		public static IWebHostBuilder UseShutdownTimeout(this IWebHostBuilder hostBuilder, TimeSpan timeout)
		{
			throw null;
		}

		public static IWebHost Start(this IWebHostBuilder hostBuilder, params string[] urls)
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

		public static bool IsStaging(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}

		public static bool IsProduction(this IHostingEnvironment hostingEnvironment)
		{
			throw null;
		}

		public static bool IsEnvironment(this IHostingEnvironment hostingEnvironment, string environmentName)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\HostingStartupAttribute.cs
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Hosting
{
	[AttributeUsage(AttributeTargets.Assembly, Inherited = false, AllowMultiple = true)]
	public sealed class HostingStartupAttribute : Attribute
	{
		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
		public Type HostingStartupType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HostingStartupAttribute([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type hostingStartupType)
		{
			throw null;
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

		CancellationToken ApplicationStopping
		{
			get;
		}

		CancellationToken ApplicationStopped
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
		string EnvironmentName
		{
			get;
			set;
		}

		string ApplicationName
		{
			get;
			set;
		}

		string WebRootPath
		{
			get;
			set;
		}

		IFileProvider WebRootFileProvider
		{
			get;
			set;
		}

		string ContentRootPath
		{
			get;
			set;
		}

		IFileProvider ContentRootFileProvider
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
		IServiceProvider ConfigureServices(IServiceCollection services);

		void Configure(IApplicationBuilder app);
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

		IWebHostBuilder ConfigureServices(Action<IServiceCollection> configureServices);

		IWebHostBuilder ConfigureServices(Action<WebHostBuilderContext, IServiceCollection> configureServices);

		string? GetSetting(string key);

		IWebHostBuilder UseSetting(string key, string? value);
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\IWebHostEnvironment.cs
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace Microsoft.AspNetCore.Hosting
{
	public interface IWebHostEnvironment : IHostEnvironment
	{
		string WebRootPath
		{
			get;
			set;
		}

		IFileProvider WebRootFileProvider
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public WebHostBuilderContext()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Abstractions\Microsoft.AspNetCore.Hosting\WebHostDefaults.cs
namespace Microsoft.AspNetCore.Hosting
{
	public static class WebHostDefaults
	{
		public static readonly string ApplicationKey;

		public static readonly string StartupAssemblyKey;

		public static readonly string HostingStartupAssembliesKey;

		public static readonly string HostingStartupExcludeAssembliesKey;

		public static readonly string DetailedErrorsKey;

		public static readonly string EnvironmentKey;

		public static readonly string WebRootKey;

		public static readonly string CaptureStartupErrorsKey;

		public static readonly string ServerUrlsKey;

		public static readonly string ContentRootKey;

		public static readonly string PreferHostingUrlsKey;

		public static readonly string PreventHostingStartupKey;

		public static readonly string SuppressStatusMessagesKey;

		public static readonly string ShutdownTimeoutKey;

		public static readonly string StaticWebAssetsKey;
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server\IHttpApplication.cs
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Hosting.Server
{
	public interface IHttpApplication<TContext> where TContext : notnull
	{
		TContext CreateContext(IFeatureCollection contextFeatures);

		Task ProcessRequestAsync(TContext context);

		void DisposeContext(TContext context, Exception exception);
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

		Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken cancellationToken) where TContext : notnull;

		Task StopAsync(CancellationToken cancellationToken);
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server\IServerIntegratedAuth.cs
namespace Microsoft.AspNetCore.Hosting.Server
{
	public interface IServerIntegratedAuth
	{
		bool IsEnabled
		{
			get;
		}

		string? AuthenticationScheme
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
				throw null;
			}
		}

		public string? AuthenticationScheme
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ServerIntegratedAuth()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Hosting.Server.Abstractions\Microsoft.AspNetCore.Hosting.Server.Abstractions\IHostContextContainer.cs
namespace Microsoft.AspNetCore.Hosting.Server.Abstractions
{
	public interface IHostContextContainer<TContext> where TContext : notnull
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
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Html
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public class HtmlContentBuilder : IHtmlContentBuilder, IHtmlContentContainer, IHtmlContent
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
			throw null;
		}

		public HtmlContentBuilder(int capacity)
		{
			throw null;
		}

		public HtmlContentBuilder(IList<object> entries)
		{
			throw null;
		}

		public IHtmlContentBuilder Append(string? unencoded)
		{
			throw null;
		}

		public IHtmlContentBuilder AppendHtml(IHtmlContent? htmlContent)
		{
			throw null;
		}

		public IHtmlContentBuilder AppendHtml(string? encoded)
		{
			throw null;
		}

		public IHtmlContentBuilder Clear()
		{
			throw null;
		}

		public void CopyTo(IHtmlContentBuilder destination)
		{
			throw null;
		}

		public void MoveTo(IHtmlContentBuilder destination)
		{
			throw null;
		}

		public void WriteTo(TextWriter writer, HtmlEncoder encoder)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Html.Abstractions\Microsoft.AspNetCore.Html\HtmlContentBuilderExtensions.cs
using System;

namespace Microsoft.AspNetCore.Html
{
	public static class HtmlContentBuilderExtensions
	{
		public static IHtmlContentBuilder AppendFormat(this IHtmlContentBuilder builder, string format, params object[] args)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendFormat(this IHtmlContentBuilder builder, IFormatProvider formatProvider, string format, params object[] args)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendLine(this IHtmlContentBuilder builder)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendLine(this IHtmlContentBuilder builder, string unencoded)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendLine(this IHtmlContentBuilder builder, IHtmlContent content)
		{
			throw null;
		}

		public static IHtmlContentBuilder AppendHtmlLine(this IHtmlContentBuilder builder, string encoded)
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
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Html
{
	[DebuggerDisplay("{DebuggerToString()}")]
	public class HtmlFormattableString : IHtmlContent
	{
		private class EncodingFormatProvider : IFormatProvider, ICustomFormatter
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			public EncodingFormatProvider(IFormatProvider formatProvider, HtmlEncoder encoder)
			{
				throw null;
			}

			public string Format(string? format, object? arg, IFormatProvider? formatProvider)
			{
				throw null;
			}

			public object? GetFormat(Type? formatType)
			{
				throw null;
			}
		}

		public HtmlFormattableString(string format, params object[] args)
		{
			throw null;
		}

		public HtmlFormattableString(IFormatProvider? formatProvider, string format, params object[] args)
		{
			throw null;
		}

		public void WriteTo(TextWriter writer, HtmlEncoder encoder)
		{
			throw null;
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
		public static readonly HtmlString NewLine;

		public static readonly HtmlString Empty;

		public string? Value
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(2)]
		public HtmlString(string? value)
		{
			throw null;
		}

		public void WriteTo(TextWriter writer, HtmlEncoder encoder)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
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
	public interface IHtmlContentBuilder : IHtmlContentContainer, IHtmlContent
	{
		IHtmlContentBuilder AppendHtml(IHtmlContent content);

		IHtmlContentBuilder Append(string unencoded);

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

		public IDictionary<string, object?> Properties
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ApplicationBuilder(IServiceProvider serviceProvider)
		{
			throw null;
		}

		public ApplicationBuilder(IServiceProvider serviceProvider, object server)
		{
			throw null;
		}

		public IApplicationBuilder Use(Func<RequestDelegate, RequestDelegate> middleware)
		{
			throw null;
		}

		public IApplicationBuilder New()
		{
			throw null;
		}

		public RequestDelegate Build()
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
			[CompilerGenerated]
			internal set
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

		public bool IsUnixPipe
		{
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

		public override string ToString()
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public static BindingAddress Parse(string address)
		{
			throw null;
		}

		public BindingAddress()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\DefaultHttpContext.cs
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Features.Authentication;
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
		private struct FeatureInterfaces
		{
			public IItemsFeature? Items;

			public IServiceProvidersFeature? ServiceProviders;

			public IHttpAuthenticationFeature? Authentication;

			public IHttpRequestLifetimeFeature? Lifetime;

			public ISessionFeature? Session;

			public IHttpRequestIdentifierFeature? RequestIdentifier;
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

		public override HttpRequest Request
		{
			get
			{
				throw null;
			}
		}

		public override HttpResponse Response
		{
			get
			{
				throw null;
			}
		}

		public override ConnectionInfo Connection
		{
			get
			{
				throw null;
			}
		}

		public override WebSocketManager WebSockets
		{
			get
			{
				throw null;
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
				throw null;
			}
		}

		public override IDictionary<object, object?> Items
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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

		public DefaultHttpContext()
		{
			throw null;
		}

		public DefaultHttpContext(IFeatureCollection features)
		{
			throw null;
		}

		public void Initialize(IFeatureCollection features)
		{
			throw null;
		}

		public void Uninitialize()
		{
			throw null;
		}

		public override void Abort()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\FormCollection.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class FormCollection : IFormCollection, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		public struct Enumerator : IEnumerator<KeyValuePair<string, StringValues>>, IEnumerator, IDisposable
		{
			private Dictionary<string, StringValues>.Enumerator _dictionaryEnumerator;

			private bool _notEmpty;

			public KeyValuePair<string, StringValues> Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				[System.Runtime.CompilerServices.NullableContext(1)]
				get
				{
					throw null;
				}
			}

			internal Enumerator(Dictionary<string, StringValues>.Enumerator dictionaryEnumerator)
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Dispose()
			{
				throw null;
			}

			void IEnumerator.Reset()
			{
				throw null;
			}
		}

		public static readonly FormCollection Empty;

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

		public int Count
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

		[System.Runtime.CompilerServices.NullableContext(2)]
		public FormCollection(Dictionary<string, StringValues>? fields, IFormFileCollection? files = null)
		{
			throw null;
		}

		public bool ContainsKey(string key)
		{
			throw null;
		}

		public bool TryGetValue(string key, out StringValues value)
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
				throw null;
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
				throw null;
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

		public string FileName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FormFile(Stream baseStream, long baseStreamOffset, long length, string name, string fileName)
		{
			throw null;
		}

		public Stream OpenReadStream()
		{
			throw null;
		}

		public void CopyTo(Stream target)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CCopyToAsync_003Ed__25))]
		[DebuggerStepThrough]
		public Task CopyToAsync(Stream target, CancellationToken cancellationToken = default(CancellationToken))
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
	public class FormFileCollection : List<IFormFile>, IFormFileCollection, IReadOnlyList<IFormFile>, IEnumerable<IFormFile>, IEnumerable, IReadOnlyCollection<IFormFile>
	{
		public IFormFile? this[string name]
		{
			get
			{
				throw null;
			}
		}

		public IFormFile? GetFile(string name)
		{
			throw null;
		}

		public IReadOnlyList<IFormFile> GetFiles(string name)
		{
			throw null;
		}

		public FormFileCollection()
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
	public class HeaderDictionary : IHeaderDictionary, IDictionary<string, StringValues>, ICollection<KeyValuePair<string, StringValues>>, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		public struct Enumerator : IEnumerator<KeyValuePair<string, StringValues>>, IEnumerator, IDisposable
		{
			private Dictionary<string, StringValues>.Enumerator _dictionaryEnumerator;

			private bool _notEmpty;

			public KeyValuePair<string, StringValues> Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				[System.Runtime.CompilerServices.NullableContext(1)]
				get
				{
					throw null;
				}
			}

			internal Enumerator(Dictionary<string, StringValues>.Enumerator dictionaryEnumerator)
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Dispose()
			{
				throw null;
			}

			void IEnumerator.Reset()
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
			set
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
				throw null;
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

		public ICollection<StringValues> Values
		{
			get
			{
				throw null;
			}
		}

		public HeaderDictionary()
		{
			throw null;
		}

		public HeaderDictionary(Dictionary<string, StringValues>? store)
		{
			throw null;
		}

		public HeaderDictionary(int capacity)
		{
			throw null;
		}

		public void Add(KeyValuePair<string, StringValues> item)
		{
			throw null;
		}

		public void Add(string key, StringValues value)
		{
			throw null;
		}

		public void Clear()
		{
			throw null;
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

		public bool TryGetValue(string key, out StringValues value)
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
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\HttpContextAccessor.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class HttpContextAccessor : IHttpContextAccessor
	{
		private class HttpContextHolder
		{
			public HttpContext? Context;

			public HttpContextHolder()
			{
				throw null;
			}
		}

		public HttpContext? HttpContext
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			set
			{
				throw null;
			}
		}

		public HttpContextAccessor()
		{
			throw null;
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
			throw null;
		}

		public HttpContextFactory(IOptions<FormOptions> formOptions, IServiceScopeFactory serviceScopeFactory)
		{
			throw null;
		}

		public HttpContextFactory(IOptions<FormOptions> formOptions, IHttpContextAccessor? httpContextAccessor)
		{
			throw null;
		}

		public HttpContextFactory(IOptions<FormOptions> formOptions, IServiceScopeFactory serviceScopeFactory, IHttpContextAccessor? httpContextAccessor)
		{
			throw null;
		}

		public HttpContext Create(IFeatureCollection featureCollection)
		{
			throw null;
		}

		public void Dispose(HttpContext httpContext)
		{
			throw null;
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
			throw null;
		}

		public static void EnableBuffering(this HttpRequest request, int bufferThreshold)
		{
			throw null;
		}

		public static void EnableBuffering(this HttpRequest request, long bufferLimit)
		{
			throw null;
		}

		public static void EnableBuffering(this HttpRequest request, int bufferThreshold, long bufferLimit)
		{
			throw null;
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
			throw null;
		}

		public IMiddleware? Create(Type middlewareType)
		{
			throw null;
		}

		public void Release(IMiddleware middleware)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http\QueryCollection.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class QueryCollection : IQueryCollection, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		public struct Enumerator : IEnumerator<KeyValuePair<string, StringValues>>, IEnumerator, IDisposable
		{
			private Dictionary<string, StringValues>.Enumerator _dictionaryEnumerator;

			private bool _notEmpty;

			public KeyValuePair<string, StringValues> Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				[System.Runtime.CompilerServices.NullableContext(1)]
				get
				{
					throw null;
				}
			}

			internal Enumerator(Dictionary<string, StringValues>.Enumerator dictionaryEnumerator)
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Dispose()
			{
				throw null;
			}

			void IEnumerator.Reset()
			{
				throw null;
			}
		}

		public static readonly QueryCollection Empty;

		public StringValues this[string key]
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

		public ICollection<string> Keys
		{
			get
			{
				throw null;
			}
		}

		public QueryCollection()
		{
			throw null;
		}

		public QueryCollection(Dictionary<string, StringValues> store)
		{
			throw null;
		}

		public QueryCollection(QueryCollection store)
		{
			throw null;
		}

		public QueryCollection(int capacity)
		{
			throw null;
		}

		public bool ContainsKey(string key)
		{
			throw null;
		}

		public bool TryGetValue(string key, out StringValues value)
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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public static class SendFileFallback
	{
		[AsyncStateMachine(typeof(_003CSendFileAsync_003Ed__0))]
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
		public Stream Stream
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IHttpResponseBodyFeature? PriorFeature
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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
			throw null;
		}

		public StreamResponseBodyFeature(Stream stream, IHttpResponseBodyFeature priorFeature)
		{
			throw null;
		}

		public virtual void DisableBuffering()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CSendFileAsync_003Ed__15))]
		[DebuggerStepThrough]
		public virtual Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public virtual Task StartAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CCompleteAsync_003Ed__17))]
		[DebuggerStepThrough]
		public virtual Task CompleteAsync()
		{
			throw null;
		}

		public void Dispose()
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
				throw null;
			}
		}

		public DefaultSessionFeature()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\FormFeature.cs
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public class FormFeature : IFormFeature
	{
		public bool HasFormContentType
		{
			get
			{
				throw null;
			}
		}

		public IFormCollection? Form
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			set
			{
				throw null;
			}
		}

		public FormFeature(IFormCollection form)
		{
			throw null;
		}

		public FormFeature(HttpRequest request)
		{
			throw null;
		}

		public FormFeature(HttpRequest request, FormOptions options)
		{
			throw null;
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
		internal static readonly FormOptions Default;

		public const int DefaultMemoryBufferThreshold = 65536;

		public const int DefaultBufferBodyLengthLimit = 134217728;

		public const int DefaultMultipartBoundaryLengthLimit = 128;

		public const long DefaultMultipartBodyLengthLimit = 134217728L;

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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public FormOptions()
		{
			throw null;
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
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public IPAddress? LocalIpAddress
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public IPAddress? RemoteIpAddress
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public HttpConnectionFeature()
		{
			throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public HttpRequestFeature()
		{
			throw null;
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
				throw null;
			}
		}

		public HttpRequestIdentifierFeature()
		{
			throw null;
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
				throw null;
			}
		}

		public void Abort()
		{
			throw null;
		}

		public HttpRequestLifetimeFeature()
		{
			throw null;
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
				throw null;
			}
		}

		public string? ReasonPhrase
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
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
				throw null;
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
				throw null;
			}
		}

		public virtual bool HasStarted
		{
			get
			{
				throw null;
			}
		}

		public HttpResponseFeature()
		{
			throw null;
		}

		public virtual void OnStarting(Func<object, Task> callback, object state)
		{
			throw null;
		}

		public virtual void OnCompleted(Func<object, Task> callback, object state)
		{
			throw null;
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
		public IDictionary<object, object?> Items
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public ItemsFeature()
		{
			throw null;
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
				throw null;
			}
		}

		public QueryFeature(IQueryCollection query)
		{
			throw null;
		}

		public QueryFeature(IFeatureCollection features)
		{
			throw null;
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
			throw null;
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
				throw null;
			}
		}

		public RequestCookiesFeature(IRequestCookieCollection cookies)
		{
			throw null;
		}

		public RequestCookiesFeature(IFeatureCollection features)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\RequestServicesFeature.cs
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public class RequestServicesFeature : IServiceProvidersFeature, IDisposable, IAsyncDisposable
	{
		public IServiceProvider RequestServices
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public RequestServicesFeature(HttpContext context, IServiceScopeFactory? scopeFactory)
		{
			throw null;
		}

		public ValueTask DisposeAsync()
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http\Microsoft.AspNetCore.Http.Features\ResponseCookiesFeature.cs
using Microsoft.Extensions.ObjectPool;
using System;
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
			throw null;
		}

		[Obsolete("This constructor is obsolete and will be removed in a future version.")]
		public ResponseCookiesFeature(IFeatureCollection features, ObjectPool<StringBuilder>? builderPool)
		{
			throw null;
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
				throw null;
			}
		}

		public RouteValuesFeature()
		{
			throw null;
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
				throw null;
			}
		}

		public ServiceProvidersFeature()
		{
			throw null;
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
		public X509Certificate2? ClientCertificate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public Task<X509Certificate2?> GetClientCertificateAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public TlsConnectionFeature()
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
		public ClaimsPrincipal? User
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public HttpAuthenticationFeature()
		{
			throw null;
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


// Microsoft.AspNetCore.Http\Microsoft.Extensions.Internal\CopyOnWriteDictionaryHolder.cs
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Extensions.Internal
{
	internal struct CopyOnWriteDictionaryHolder<TKey, TValue> where TKey : notnull
	{
		private readonly Dictionary<TKey, TValue> _source;

		private Dictionary<TKey, TValue>? _copy;

		public bool HasBeenCopied
		{
			get
			{
				throw null;
			}
		}

		public Dictionary<TKey, TValue> ReadDictionary
		{
			get
			{
				throw null;
			}
		}

		public Dictionary<TKey, TValue> WriteDictionary
		{
			get
			{
				throw null;
			}
		}

		public Dictionary<TKey, TValue>.KeyCollection Keys
		{
			get
			{
				throw null;
			}
		}

		public Dictionary<TKey, TValue>.ValueCollection Values
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

		public bool IsReadOnly
		{
			get
			{
				throw null;
			}
		}

		public TValue this[TKey key]
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public CopyOnWriteDictionaryHolder(Dictionary<TKey, TValue> source)
		{
			throw null;
		}

		public CopyOnWriteDictionaryHolder(CopyOnWriteDictionaryHolder<TKey, TValue> source)
		{
			throw null;
		}

		public bool ContainsKey(TKey key)
		{
			throw null;
		}

		public void Add(TKey key, TValue value)
		{
			throw null;
		}

		public bool Remove(TKey key)
		{
			throw null;
		}

		public bool TryGetValue(TKey key, [MaybeNullWhen(false)] out TValue value)
		{
			throw null;
		}

		public void Add(KeyValuePair<TKey, TValue> item)
		{
			throw null;
		}

		public void Clear()
		{
			throw null;
		}

		public bool Contains(KeyValuePair<TKey, TValue> item)
		{
			throw null;
		}

		public void CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
		{
			throw null;
		}

		public bool Remove(KeyValuePair<TKey, TValue> item)
		{
			throw null;
		}

		public Dictionary<TKey, TValue>.Enumerator GetEnumerator()
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
		public RequestDelegate? RequestDelegate
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? DisplayName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public IList<object> Metadata
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public abstract Endpoint Build();

		protected EndpointBuilder()
		{
			throw null;
		}
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

		IFeatureCollection ServerFeatures
		{
			get;
		}

		IDictionary<string, object?> Properties
		{
			get;
		}

		IApplicationBuilder Use(Func<RequestDelegate, RequestDelegate> middleware);

		IApplicationBuilder New();

		RequestDelegate Build();
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

		public static IApplicationBuilder Map(this IApplicationBuilder app, PathString pathMatch, bool preserveMatchedPathSegment, Action<IApplicationBuilder> configuration)
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
			throw null;
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
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Builder
{
	public static class UseMiddlewareExtensions
	{
		internal const string InvokeMethodName = "Invoke";

		internal const string InvokeAsyncMethodName = "InvokeAsync";

		public static IApplicationBuilder UseMiddleware<[DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] TMiddleware>(this IApplicationBuilder app, params object[] args)
		{
			throw null;
		}

		public static IApplicationBuilder UseMiddleware(this IApplicationBuilder app, [DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] Type middleware, params object[] args)
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class MapMiddleware
	{
		public MapMiddleware(RequestDelegate next, MapOptions options)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__3))]
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
				throw null;
			}
		}

		public RequestDelegate? Branch
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public bool PreserveMatchedPathSegment
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public MapOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder.Extensions\MapWhenMiddleware.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class MapWhenMiddleware
	{
		public MapWhenMiddleware(RequestDelegate next, MapWhenOptions options)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__3))]
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
		public Func<HttpContext, bool>? Predicate
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public RequestDelegate? Branch
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public MapWhenOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Builder.Extensions\UsePathBaseMiddleware.cs
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder.Extensions
{
	public class UsePathBaseMiddleware
	{
		public UsePathBaseMiddleware(RequestDelegate next, PathString pathBase)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__3))]
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


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\BadHttpRequestException.cs
using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class BadHttpRequestException : IOException
	{
		public int StatusCode
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public BadHttpRequestException(string message, int statusCode)
		{
			throw null;
		}

		public BadHttpRequestException(string message)
		{
			throw null;
		}

		public BadHttpRequestException(string message, int statusCode, Exception innerException)
		{
			throw null;
		}

		public BadHttpRequestException(string message, Exception innerException)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\ConnectionInfo.cs
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public abstract class ConnectionInfo
	{
		public abstract string Id
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			get;
			[System.Runtime.CompilerServices.NullableContext(1)]
			set;
		}

		public abstract IPAddress? RemoteIpAddress
		{
			get;
			set;
		}

		public abstract int RemotePort
		{
			get;
			set;
		}

		public abstract IPAddress? LocalIpAddress
		{
			get;
			set;
		}

		public abstract int LocalPort
		{
			get;
			set;
		}

		public abstract X509Certificate2? ClientCertificate
		{
			get;
			set;
		}

		public abstract Task<X509Certificate2?> GetClientCertificateAsync(CancellationToken cancellationToken = default(CancellationToken));

		protected ConnectionInfo()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\CookieBuilder.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public class CookieBuilder
	{
		public virtual string? Name
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public virtual string? Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public virtual string? Domain
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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

		public CookieBuilder()
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
		public string? DisplayName
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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

		[System.Runtime.CompilerServices.NullableContext(2)]
		public Endpoint(RequestDelegate requestDelegate, EndpointMetadataCollection? metadata, string? displayName)
		{
			throw null;
		}

		public override string? ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\EndpointHttpContextExtensions.cs
using Microsoft.AspNetCore.Http.Features;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public static class EndpointHttpContextExtensions
	{
		private class EndpointFeature : IEndpointFeature
		{
			public Endpoint? Endpoint
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
				[CompilerGenerated]
				set
				{
					throw null;
				}
			}

			public EndpointFeature()
			{
				throw null;
			}
		}

		public static Endpoint? GetEndpoint(this HttpContext context)
		{
			throw null;
		}

		public static void SetEndpoint(this HttpContext context, Endpoint? endpoint)
		{
			throw null;
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
	public sealed class EndpointMetadataCollection : IReadOnlyList<object>, IEnumerable<object>, IEnumerable, IReadOnlyCollection<object>
	{
		public struct Enumerator : IEnumerator<object?>, IEnumerator, IDisposable
		{
			private object[] _items;

			private int _index;

			public object? Current
			{
				[CompilerGenerated]
				readonly get
				{
					throw null;
				}
			}

			[System.Runtime.CompilerServices.NullableContext(1)]
			internal Enumerator(EndpointMetadataCollection collection)
			{
				throw null;
			}

			public void Dispose()
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Reset()
			{
				throw null;
			}
		}

		public static readonly EndpointMetadataCollection Empty;

		public object this[int index]
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

		public EndpointMetadataCollection(IEnumerable<object> items)
		{
			throw null;
		}

		public EndpointMetadataCollection(params object[] items)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public T? GetMetadata<T>() where T : class
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public IReadOnlyList<T> GetOrderedMetadata<T>() where T : class
		{
			throw null;
		}

		public Enumerator GetEnumerator()
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
		public static readonly FragmentString Empty;

		private readonly string _value;

		public string Value
		{
			get
			{
				throw null;
			}
		}

		public bool HasValue
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

		public override string ToString()
		{
			throw null;
		}

		public string ToUriComponent()
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

		public bool Equals(FragmentString other)
		{
			throw null;
		}

		public override bool Equals(object? obj)
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
			throw null;
		}

		public static void AppendCommaSeparatedValues(this IHeaderDictionary headers, string key, params string[] values)
		{
			throw null;
		}

		public static string[] GetCommaSeparatedValues(this IHeaderDictionary headers, string key)
		{
			throw null;
		}

		public static void SetCommaSeparatedValues(this IHeaderDictionary headers, string key, params string[] values)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HeaderSegment.cs
using Microsoft.Extensions.Primitives;
using System;

namespace Microsoft.AspNetCore.Http
{
	internal readonly struct HeaderSegment : IEquatable<HeaderSegment>
	{
		private readonly StringSegment _formatting;

		private readonly StringSegment _data;

		public StringSegment Formatting
		{
			get
			{
				throw null;
			}
		}

		public StringSegment Data
		{
			get
			{
				throw null;
			}
		}

		public HeaderSegment(StringSegment formatting, StringSegment data)
		{
			throw null;
		}

		public bool Equals(HeaderSegment other)
		{
			throw null;
		}

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static bool operator ==(HeaderSegment left, HeaderSegment right)
		{
			throw null;
		}

		public static bool operator !=(HeaderSegment left, HeaderSegment right)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HeaderSegmentCollection.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	internal readonly struct HeaderSegmentCollection : IEnumerable<HeaderSegment>, IEnumerable, IEquatable<HeaderSegmentCollection>
	{
		public struct Enumerator : IEnumerator<HeaderSegment>, IEnumerator, IDisposable
		{
			private enum Mode
			{
				Leading,
				Value,
				ValueQuoted,
				Trailing,
				Produce
			}

			private enum Attr
			{
				Value,
				Quote,
				Delimiter,
				Whitespace
			}

			private readonly StringValues _headers;

			private int _index;

			private string _header;

			private int _headerLength;

			private int _offset;

			private int _leadingStart;

			private int _leadingEnd;

			private int _valueStart;

			private int _valueEnd;

			private int _trailingStart;

			private Mode _mode;

			public HeaderSegment Current
			{
				get
				{
					throw null;
				}
			}

			object IEnumerator.Current
			{
				[System.Runtime.CompilerServices.NullableContext(1)]
				get
				{
					throw null;
				}
			}

			public Enumerator(StringValues headers)
			{
				throw null;
			}

			public void Dispose()
			{
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Reset()
			{
				throw null;
			}
		}

		private readonly StringValues _headers;

		public HeaderSegmentCollection(StringValues headers)
		{
			throw null;
		}

		public bool Equals(HeaderSegmentCollection other)
		{
			throw null;
		}

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static bool operator ==(HeaderSegmentCollection left, HeaderSegmentCollection right)
		{
			throw null;
		}

		public static bool operator !=(HeaderSegmentCollection left, HeaderSegmentCollection right)
		{
			throw null;
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		IEnumerator<HeaderSegment> IEnumerable<HeaderSegment>.GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
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
		private readonly string _value;

		public string Value
		{
			get
			{
				throw null;
			}
		}

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

		public HostString(string value)
		{
			throw null;
		}

		public HostString(string host, int port)
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

		public static HostString FromUriComponent(string uriComponent)
		{
			throw null;
		}

		public static HostString FromUriComponent(Uri uri)
		{
			throw null;
		}

		public static bool MatchesAny(StringSegment value, IList<StringSegment> patterns)
		{
			throw null;
		}

		public bool Equals(HostString other)
		{
			throw null;
		}

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public override int GetHashCode()
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
		public abstract IFeatureCollection Features
		{
			get;
		}

		public abstract HttpRequest Request
		{
			get;
		}

		public abstract HttpResponse Response
		{
			get;
		}

		public abstract ConnectionInfo Connection
		{
			get;
		}

		public abstract WebSocketManager WebSockets
		{
			get;
		}

		public abstract ClaimsPrincipal User
		{
			get;
			set;
		}

		public abstract IDictionary<object, object?> Items
		{
			get;
			set;
		}

		public abstract IServiceProvider RequestServices
		{
			get;
			set;
		}

		public abstract CancellationToken RequestAborted
		{
			get;
			set;
		}

		public abstract string TraceIdentifier
		{
			get;
			set;
		}

		public abstract ISession Session
		{
			get;
			set;
		}

		public abstract void Abort();

		protected HttpContext()
		{
			throw null;
		}
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

		public static string GetCanonicalizedValue(string method)
		{
			throw null;
		}

		public static bool Equals(string methodA, string methodB)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\HttpProtocol.cs
using System;

namespace Microsoft.AspNetCore.Http
{
	public static class HttpProtocol
	{
		public static readonly string Http10;

		public static readonly string Http11;

		public static readonly string Http2;

		public static readonly string Http3;

		public static bool IsHttp10(string protocol)
		{
			throw null;
		}

		public static bool IsHttp11(string protocol)
		{
			throw null;
		}

		public static bool IsHttp2(string protocol)
		{
			throw null;
		}

		public static bool IsHttp3(string protocol)
		{
			throw null;
		}

		public static string GetHttpProtocol(Version version)
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
		public abstract HttpContext HttpContext
		{
			get;
		}

		public abstract string Method
		{
			get;
			set;
		}

		public abstract string Scheme
		{
			get;
			set;
		}

		public abstract bool IsHttps
		{
			get;
			set;
		}

		public abstract HostString Host
		{
			get;
			set;
		}

		public abstract PathString PathBase
		{
			get;
			set;
		}

		public abstract PathString Path
		{
			get;
			set;
		}

		public abstract QueryString QueryString
		{
			get;
			set;
		}

		public abstract IQueryCollection Query
		{
			get;
			set;
		}

		public abstract string Protocol
		{
			get;
			set;
		}

		public abstract IHeaderDictionary Headers
		{
			get;
		}

		public abstract IRequestCookieCollection Cookies
		{
			get;
			set;
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

		public abstract bool HasFormContentType
		{
			get;
		}

		public abstract IFormCollection Form
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
				throw null;
			}
		}

		public abstract Task<IFormCollection> ReadFormAsync(CancellationToken cancellationToken = default(CancellationToken));

		protected HttpRequest()
		{
			throw null;
		}
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
		public abstract HttpContext HttpContext
		{
			get;
		}

		public abstract int StatusCode
		{
			get;
			set;
		}

		public abstract IHeaderDictionary Headers
		{
			get;
		}

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

		public abstract void OnStarting(Func<object, Task> callback, object state);

		public virtual void OnStarting(Func<Task> callback)
		{
			throw null;
		}

		public abstract void OnCompleted(Func<object, Task> callback, object state);

		public virtual void RegisterForDispose(IDisposable disposable)
		{
			throw null;
		}

		public virtual void RegisterForDisposeAsync(IAsyncDisposable disposable)
		{
			throw null;
		}

		public virtual void OnCompleted(Func<Task> callback)
		{
			throw null;
		}

		public virtual void Redirect(string location)
		{
			throw null;
		}

		public abstract void Redirect(string location, bool permanent);

		public virtual Task StartAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public virtual Task CompleteAsync()
		{
			throw null;
		}

		protected HttpResponse()
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
		public static Task WriteAsync(this HttpResponse response, string text, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task WriteAsync(this HttpResponse response, string text, Encoding encoding, CancellationToken cancellationToken = default(CancellationToken))
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
		HttpContext? HttpContext
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
		IMiddleware? Create(Type middlewareType);

		void Release(IMiddleware middleware);
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\PathString.cs
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	[TypeConverter(typeof(PathStringConverter))]
	public readonly struct PathString : IEquatable<PathString>
	{
		public static readonly PathString Empty;

		private readonly string? _value;

		public string? Value
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
		}

		public bool HasValue
		{
			get
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(2)]
		public PathString(string? value)
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

		public static PathString FromUriComponent(string uriComponent)
		{
			throw null;
		}

		public static PathString FromUriComponent(Uri uri)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, StringComparison comparisonType)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, out PathString remaining)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, StringComparison comparisonType, out PathString remaining)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, out PathString matched, out PathString remaining)
		{
			throw null;
		}

		public bool StartsWithSegments(PathString other, StringComparison comparisonType, out PathString matched, out PathString remaining)
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

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public static bool operator ==(PathString left, PathString right)
		{
			throw null;
		}

		public static bool operator !=(PathString left, PathString right)
		{
			throw null;
		}

		public static string operator +(string left, PathString right)
		{
			throw null;
		}

		public static string operator +(PathString left, string? right)
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

		[System.Runtime.CompilerServices.NullableContext(2)]
		public static implicit operator PathString(string? s)
		{
			throw null;
		}

		public static implicit operator string(PathString path)
		{
			throw null;
		}

		internal static PathString ConvertFromString(string? s)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http\QueryString.cs
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http
{
	public readonly struct QueryString : IEquatable<QueryString>
	{
		public static readonly QueryString Empty;

		public string? Value
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool HasValue
		{
			get
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(2)]
		public QueryString(string? value)
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

		public static QueryString FromUriComponent(string uriComponent)
		{
			throw null;
		}

		public static QueryString FromUriComponent(Uri uri)
		{
			throw null;
		}

		public static QueryString Create(string name, string value)
		{
			throw null;
		}

		public static QueryString Create(IEnumerable<KeyValuePair<string, string?>> parameters)
		{
			throw null;
		}

		public static QueryString Create(IEnumerable<KeyValuePair<string, StringValues>> parameters)
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

		public bool Equals(QueryString other)
		{
			throw null;
		}

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public override int GetHashCode()
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

		public static QueryString operator +(QueryString left, QueryString right)
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
		public static StringValues GetDeclaredTrailers(this HttpRequest request)
		{
			throw null;
		}

		public static bool SupportsTrailers(this HttpRequest request)
		{
			throw null;
		}

		public static bool CheckTrailersAvailable(this HttpRequest request)
		{
			throw null;
		}

		public static StringValues GetTrailer(this HttpRequest request, string trailerName)
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
		public static void DeclareTrailer(this HttpResponse response, string trailerName)
		{
			throw null;
		}

		public static bool SupportsTrailers(this HttpResponse response)
		{
			throw null;
		}

		public static void AppendTrailer(this HttpResponse response, string trailerName, StringValues trailerValues)
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

		public const int Status413RequestEntityTooLarge = 413;

		public const int Status413PayloadTooLarge = 413;

		public const int Status414RequestUriTooLong = 414;

		public const int Status414UriTooLong = 414;

		public const int Status415UnsupportedMediaType = 415;

		public const int Status416RequestedRangeNotSatisfiable = 416;

		public const int Status416RangeNotSatisfiable = 416;

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

		public abstract Task<WebSocket> AcceptWebSocketAsync(string? subProtocol);

		protected WebSocketManager()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Abstractions\Microsoft.AspNetCore.Http.Features\IEndpointFeature.cs
namespace Microsoft.AspNetCore.Http.Features
{
	public interface IEndpointFeature
	{
		Endpoint? Endpoint
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
		internal ConnectionEndpointRouteBuilder(IEndpointConventionBuilder endpointConventionBuilder)
		{
			throw null;
		}

		public void Add(Action<EndpointBuilder> convention)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Builder\ConnectionEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Routing;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Builder
{
	public static class ConnectionEndpointRouteBuilderExtensions
	{
		private class CompositeEndpointConventionBuilder : IEndpointConventionBuilder
		{
			public CompositeEndpointConventionBuilder(List<IEndpointConventionBuilder> endpointConventionBuilders)
			{
				throw null;
			}

			public void Add(Action<EndpointBuilder> convention)
			{
				throw null;
			}
		}

		public static ConnectionEndpointRouteBuilder MapConnections(this IEndpointRouteBuilder endpoints, string pattern, Action<IConnectionBuilder> configure)
		{
			throw null;
		}

		public static ConnectionEndpointRouteBuilder MapConnectionHandler<TConnectionHandler>(this IEndpointRouteBuilder endpoints, string pattern) where TConnectionHandler : ConnectionHandler
		{
			throw null;
		}

		public static ConnectionEndpointRouteBuilder MapConnectionHandler<TConnectionHandler>(this IEndpointRouteBuilder endpoints, string pattern, Action<HttpConnectionDispatcherOptions>? configureOptions) where TConnectionHandler : ConnectionHandler
		{
			throw null;
		}

		public static ConnectionEndpointRouteBuilder MapConnections(this IEndpointRouteBuilder endpoints, string pattern, HttpConnectionDispatcherOptions options, Action<IConnectionBuilder> configure)
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
				throw null;
			}
		}

		public ConnectionOptions()
		{
			throw null;
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
			throw null;
		}

		public ConnectionOptionsSetup()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\HttpConnectionContextExtensions.cs
using Microsoft.AspNetCore.Connections;

namespace Microsoft.AspNetCore.Http.Connections
{
	public static class HttpConnectionContextExtensions
	{
		public static HttpContext? GetHttpContext(this ConnectionContext connection)
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
		public IList<IAuthorizeData> AuthorizationData
		{
			[CompilerGenerated]
			get
			{
				throw null;
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
				throw null;
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

		public LongPollingOptions LongPolling
		{
			[CompilerGenerated]
			get
			{
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public HttpConnectionDispatcherOptions()
		{
			throw null;
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
				throw null;
			}
		}

		public LongPollingOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections\NegotiateMetadata.cs
namespace Microsoft.AspNetCore.Http.Connections
{
	public class NegotiateMetadata
	{
		public NegotiateMetadata()
		{
			throw null;
		}
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
				throw null;
			}
		}

		public Func<IList<string>, string>? SubProtocolSelector
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public WebSocketOptions()
		{
			throw null;
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


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections.Internal\HttpConnectionStatus.cs
namespace Microsoft.AspNetCore.Http.Connections.Internal
{
	internal enum HttpConnectionStatus
	{
		Inactive,
		Active,
		Disposed
	}
}


// Microsoft.AspNetCore.Http.Connections\Microsoft.AspNetCore.Http.Connections.Internal.Transports\IHttpTransport.cs
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Connections.Internal.Transports
{
	internal interface IHttpTransport
	{
		Task ProcessRequestAsync(HttpContext context, CancellationToken token);
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

namespace Microsoft.Extensions.Internal
{
	internal struct ValueStopwatch
	{
		private static readonly double TimestampToTicks;

		private long _startTimestamp;

		public bool IsActive
		{
			get
			{
				throw null;
			}
		}

		public static ValueStopwatch StartNew()
		{
			throw null;
		}

		public TimeSpan GetElapsedTime()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Connections\System.Threading.Tasks\NoThrowAwaiter.cs
using System.Runtime.CompilerServices;

namespace System.Threading.Tasks
{
	internal readonly struct NoThrowAwaiter : ICriticalNotifyCompletion, INotifyCompletion
	{
		private readonly Task _task;

		public bool IsCompleted
		{
			get
			{
				throw null;
			}
		}

		public NoThrowAwaiter(Task task)
		{
			throw null;
		}

		public NoThrowAwaiter GetAwaiter()
		{
			throw null;
		}

		public void GetResult()
		{
			throw null;
		}

		public void OnCompleted(Action continuation)
		{
			throw null;
		}

		public void UnsafeOnCompleted(Action continuation)
		{
			throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public AvailableTransport()
		{
			throw null;
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
		public static void WriteResponse(NegotiationResponse response, IBufferWriter<byte> output)
		{
			throw null;
		}

		public static NegotiationResponse ParseResponse(ReadOnlySpan<byte> content)
		{
			throw null;
		}

		[Obsolete("This method is obsolete and will be removed in a future version. The recommended alternative is ParseResponse(ReadOnlySpan{byte}).")]
		public static NegotiationResponse ParseResponse(Stream content)
		{
			throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public NegotiationResponse()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\HeaderDictionaryTypeExtensions.cs
using Microsoft.AspNetCore.Http.Headers;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public static class HeaderDictionaryTypeExtensions
	{
		public static RequestHeaders GetTypedHeaders(this HttpRequest request)
		{
			throw null;
		}

		public static ResponseHeaders GetTypedHeaders(this HttpResponse response)
		{
			throw null;
		}

		internal static DateTimeOffset? GetDate(this IHeaderDictionary headers, string name)
		{
			throw null;
		}

		internal static void Set(this IHeaderDictionary headers, string name, object value)
		{
			throw null;
		}

		internal static void SetList<T>(this IHeaderDictionary headers, string name, IList<T> values)
		{
			throw null;
		}

		public static void AppendList<T>(this IHeaderDictionary Headers, string name, IList<T> values)
		{
			throw null;
		}

		internal static void SetDate(this IHeaderDictionary headers, string name, DateTimeOffset? value)
		{
			throw null;
		}

		internal static T Get<T>(this IHeaderDictionary headers, string name)
		{
			throw null;
		}

		internal static IList<T> GetList<T>(this IHeaderDictionary headers, string name)
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


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\HttpRequestJsonExtensions.cs
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public static class HttpRequestJsonExtensions
	{
		public static ValueTask<TValue?> ReadFromJsonAsync<TValue>(this HttpRequest request, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadFromJsonAsync_003Ed__1<>))]
		[DebuggerStepThrough]
		public static ValueTask<TValue?> ReadFromJsonAsync<TValue>(this HttpRequest request, JsonSerializerOptions? options, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static ValueTask<object?> ReadFromJsonAsync(this HttpRequest request, Type type, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadFromJsonAsync_003Ed__3))]
		[DebuggerStepThrough]
		public static ValueTask<object?> ReadFromJsonAsync(this HttpRequest request, Type type, JsonSerializerOptions? options, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static bool HasJsonContentType(this HttpRequest request)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http\HttpResponseJsonExtensions.cs
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http
{
	public static class HttpResponseJsonExtensions
	{
		public static Task WriteAsJsonAsync<TValue>(this HttpResponse response, [AllowNull] TValue value, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task WriteAsJsonAsync<TValue>(this HttpResponse response, [AllowNull] TValue value, JsonSerializerOptions? options, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task WriteAsJsonAsync<TValue>(this HttpResponse response, [AllowNull] TValue value, JsonSerializerOptions? options, string? contentType, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task WriteAsJsonAsync(this HttpResponse response, object? value, Type type, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task WriteAsJsonAsync(this HttpResponse response, object? value, Type type, JsonSerializerOptions? options, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task WriteAsJsonAsync(this HttpResponse response, object? value, Type type, JsonSerializerOptions? options, string? contentType, CancellationToken cancellationToken = default(CancellationToken))
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
			throw null;
		}

		public static void Redirect(this HttpResponse response, string location, bool permanent, bool preserveMethod)
		{
			throw null;
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
		public static Task SendFileAsync(this HttpResponse response, IFileInfo file, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendFileAsync(this HttpResponse response, IFileInfo file, long offset, long? count, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendFileAsync(this HttpResponse response, string fileName, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendFileAsync(this HttpResponse response, string fileName, long offset, long? count, CancellationToken cancellationToken = default(CancellationToken))
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
		public static void SetInt32(this ISession session, string key, int value)
		{
			throw null;
		}

		public static int? GetInt32(this ISession session, string key)
		{
			throw null;
		}

		public static void SetString(this ISession session, string key, string value)
		{
			throw null;
		}

		public static string GetString(this ISession session, string key)
		{
			throw null;
		}

		public static byte[] Get(this ISession session, string key)
		{
			throw null;
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
using Microsoft.Extensions.Primitives;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http.Extensions
{
	public class QueryBuilder : IEnumerable<KeyValuePair<string, string>>, IEnumerable
	{
		public QueryBuilder()
		{
			throw null;
		}

		public QueryBuilder(IEnumerable<KeyValuePair<string, string>> parameters)
		{
			throw null;
		}

		public QueryBuilder(IEnumerable<KeyValuePair<string, StringValues>> parameters)
		{
			throw null;
		}

		public void Add(string key, IEnumerable<string> values)
		{
			throw null;
		}

		public void Add(string key, string value)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}

		public QueryString ToQueryString()
		{
			throw null;
		}

		public override int GetHashCode()
		{
			throw null;
		}

		public override bool Equals(object obj)
		{
			throw null;
		}

		public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
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
		public static Task CopyToAsync(Stream source, Stream destination, long? count, CancellationToken cancel)
		{
			throw null;
		}

		public static Task CopyToAsync(Stream source, Stream destination, long? count, int bufferSize, CancellationToken cancel)
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
		public static string BuildRelative(PathString pathBase = default(PathString), PathString path = default(PathString), QueryString query = default(QueryString), FragmentString fragment = default(FragmentString))
		{
			throw null;
		}

		public static string BuildAbsolute(string scheme, HostString host, PathString pathBase = default(PathString), PathString path = default(PathString), QueryString query = default(QueryString), FragmentString fragment = default(FragmentString))
		{
			throw null;
		}

		public static void FromAbsolute(string uri, out string scheme, out HostString host, out PathString path, out QueryString query, out FragmentString fragment)
		{
			throw null;
		}

		public static string Encode(Uri uri)
		{
			throw null;
		}

		public static string GetEncodedUrl(this HttpRequest request)
		{
			throw null;
		}

		public static string GetEncodedPathAndQuery(this HttpRequest request)
		{
			throw null;
		}

		public static string GetDisplayUrl(this HttpRequest request)
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
		public IHeaderDictionary Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IList<MediaTypeHeaderValue> Accept
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public RequestHeaders(IHeaderDictionary headers)
		{
			throw null;
		}

		public T Get<T>(string name)
		{
			throw null;
		}

		public IList<T> GetList<T>(string name)
		{
			throw null;
		}

		public void Set(string name, object value)
		{
			throw null;
		}

		public void SetList<T>(string name, IList<T> values)
		{
			throw null;
		}

		public void Append(string name, object value)
		{
			throw null;
		}

		public void AppendList<T>(string name, IList<T> values)
		{
			throw null;
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
		public IHeaderDictionary Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public ResponseHeaders(IHeaderDictionary headers)
		{
			throw null;
		}

		public T Get<T>(string name)
		{
			throw null;
		}

		public IList<T> GetList<T>(string name)
		{
			throw null;
		}

		public void Set(string name, object value)
		{
			throw null;
		}

		public void SetList<T>(string name, IList<T> values)
		{
			throw null;
		}

		public void Append(string name, object value)
		{
			throw null;
		}

		public void AppendList<T>(string name, IList<T> values)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Extensions\Microsoft.AspNetCore.Http.Json\JsonOptions.cs
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Microsoft.AspNetCore.Http.Json
{
	public class JsonOptions
	{
		internal static readonly JsonSerializerOptions DefaultSerializerOptions;

		public JsonSerializerOptions SerializerOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public JsonOptions()
		{
			throw null;
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
		public string? Domain
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? Path
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public CookieOptions()
		{
			throw null;
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

		ICollection<string> Keys
		{
			get;
		}

		StringValues this[string key]
		{
			get;
		}

		IFormFileCollection Files
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
		string ContentType
		{
			get;
		}

		string ContentDisposition
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

		string FileName
		{
			get;
		}

		Stream OpenReadStream();

		void CopyTo(Stream target);

		Task CopyToAsync(Stream target, CancellationToken cancellationToken = default(CancellationToken));
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IFormFileCollection.cs
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public interface IFormFileCollection : IReadOnlyList<IFormFile>, IEnumerable<IFormFile>, IEnumerable, IReadOnlyCollection<IFormFile>
	{
		IFormFile? this[string name]
		{
			get;
		}

		IFormFile? GetFile(string name);

		IReadOnlyList<IFormFile> GetFiles(string name);
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http\IHeaderDictionary.cs
using Microsoft.Extensions.Primitives;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http
{
	public interface IHeaderDictionary : IDictionary<string, StringValues>, ICollection<KeyValuePair<string, StringValues>>, IEnumerable<KeyValuePair<string, StringValues>>, IEnumerable
	{
		new StringValues this[string key]
		{
			get;
			set;
		}

		long? ContentLength
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

		ICollection<string> Keys
		{
			get;
		}

		StringValues this[string key]
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
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Http
{
	public interface IRequestCookieCollection : IEnumerable<KeyValuePair<string, string>>, IEnumerable
	{
		int Count
		{
			get;
		}

		ICollection<string> Keys
		{
			get;
		}

		string? this[string key]
		{
			get;
		}

		bool ContainsKey(string key);

		bool TryGetValue(string key, [MaybeNullWhen(false)] out string? value);
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
		bool IsAvailable
		{
			get;
		}

		string Id
		{
			get;
		}

		IEnumerable<string> Keys
		{
			get;
		}

		Task LoadAsync(CancellationToken cancellationToken = default(CancellationToken));

		Task CommitAsync(CancellationToken cancellationToken = default(CancellationToken));

		bool TryGetValue(string key, out byte[] value);

		void Set(string key, byte[] value);

		void Remove(string key);

		void Clear();
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
		public virtual string? SubProtocol
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public WebSocketAcceptContext()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\FeatureCollection.cs
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public class FeatureCollection : IFeatureCollection, IEnumerable<KeyValuePair<Type, object>>, IEnumerable
	{
		private class KeyComparer : IEqualityComparer<KeyValuePair<Type, object>>
		{
			public bool Equals(KeyValuePair<Type, object> x, KeyValuePair<Type, object> y)
			{
				throw null;
			}

			public int GetHashCode(KeyValuePair<Type, object> obj)
			{
				throw null;
			}

			public KeyComparer()
			{
				throw null;
			}
		}

		public virtual int Revision
		{
			get
			{
				throw null;
			}
		}

		public bool IsReadOnly
		{
			get
			{
				throw null;
			}
		}

		public object? this[Type key]
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public FeatureCollection()
		{
			throw null;
		}

		public FeatureCollection(IFeatureCollection defaults)
		{
			throw null;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw null;
		}

		[IteratorStateMachine(typeof(_003CGetEnumerator_003Ed__14))]
		public IEnumerator<KeyValuePair<Type, object>> GetEnumerator()
		{
			throw null;
		}

		[return: MaybeNull]
		public TFeature Get<TFeature>()
		{
			throw null;
		}

		public void Set<TFeature>(TFeature instance)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\FeatureReference.cs
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Http.Features
{
	public struct FeatureReference<T>
	{
		private T _feature;

		private int _revision;

		public static readonly FeatureReference<T> Default;

		[return: MaybeNull]
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
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public struct FeatureReferences<TCache>
	{
		[AllowNull]
		[MaybeNull]
		public TCache Cache;

		public IFeatureCollection Collection
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public int Revision
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public FeatureReferences(IFeatureCollection collection)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Initalize(IFeatureCollection collection)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Initalize(IFeatureCollection collection, int revision)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public TFeature Fetch<TFeature, TState>([AllowNull] [MaybeNull] ref TFeature cached, TState state, Func<TState, TFeature> factory) where TFeature : class?
		{
			throw null;
		}

		public TFeature Fetch<TFeature>([AllowNull] [MaybeNull] ref TFeature cached, Func<IFeatureCollection, TFeature> factory) where TFeature : class?
		{
			throw null;
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

		int Revision
		{
			get;
		}

		object? this[Type key]
		{
			get;
			set;
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
		bool HasFormContentType
		{
			get;
		}

		IFormCollection? Form
		{
			get;
			set;
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
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpConnectionFeature
	{
		string ConnectionId
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			get;
			[System.Runtime.CompilerServices.NullableContext(1)]
			set;
		}

		IPAddress? RemoteIpAddress
		{
			get;
			set;
		}

		IPAddress? LocalIpAddress
		{
			get;
			set;
		}

		int RemotePort
		{
			get;
			set;
		}

		int LocalPort
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
		string Protocol
		{
			get;
			set;
		}

		string Scheme
		{
			get;
			set;
		}

		string Method
		{
			get;
			set;
		}

		string PathBase
		{
			get;
			set;
		}

		string Path
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

		IHeaderDictionary Headers
		{
			get;
			set;
		}

		Stream Body
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

		void DisableBuffering();

		Task StartAsync(CancellationToken cancellationToken = default(CancellationToken));

		Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken = default(CancellationToken));

		Task CompleteAsync();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features\IHttpResponseFeature.cs
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Http.Features
{
	public interface IHttpResponseFeature
	{
		int StatusCode
		{
			get;
			set;
		}

		string? ReasonPhrase
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get;
			[System.Runtime.CompilerServices.NullableContext(2)]
			set;
		}

		IHeaderDictionary Headers
		{
			get;
			set;
		}

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

		void OnStarting(Func<object, Task> callback, object state);

		void OnCompleted(Func<object, Task> callback, object state);
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
		IDictionary<object, object?> Items
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
		X509Certificate2? ClientCertificate
		{
			get;
			set;
		}

		Task<X509Certificate2?> GetClientCertificateAsync(CancellationToken cancellationToken);
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
		bool IsConsentNeeded
		{
			get;
		}

		bool HasConsent
		{
			get;
		}

		bool CanTrack
		{
			get;
		}

		void GrantConsent();

		void WithdrawConsent();

		string CreateConsentCookie();
	}
}


// Microsoft.AspNetCore.Http.Features\Microsoft.AspNetCore.Http.Features.Authentication\IHttpAuthenticationFeature.cs
using System.Security.Claims;

namespace Microsoft.AspNetCore.Http.Features.Authentication
{
	public interface IHttpAuthenticationFeature
	{
		ClaimsPrincipal? User
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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

		public IList<IPNetwork> KnownNetworks
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

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
				throw null;
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
				throw null;
			}
		}

		public ForwardedHeadersOptions()
		{
			throw null;
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
				throw null;
			}
		}

		public HttpMethodOverrideOptions()
		{
			throw null;
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
			throw null;
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
				throw null;
			}
		}

		public CertificateForwardingOptions()
		{
			throw null;
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
using System.Net;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public class ForwardedHeadersMiddleware
	{
		private struct SetOfForwarders
		{
			public string IpAndPortText;

			public IPEndPoint RemoteIpAndPort;

			public string Host;

			public string Scheme;
		}

		public ForwardedHeadersMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IOptions<ForwardedHeadersOptions> options)
		{
			throw null;
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}

		public void ApplyForwarders(HttpContext context)
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.HttpOverrides
{
	public class HttpMethodOverrideMiddleware
	{
		public HttpMethodOverrideMiddleware(RequestDelegate next, IOptions<HttpMethodOverrideOptions> options)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__4))]
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
			throw null;
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
		public HstsMiddleware(RequestDelegate next, IOptions<HstsOptions> options, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public HstsMiddleware(RequestDelegate next, IOptions<HstsOptions> options)
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public IList<string> ExcludedHosts
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HstsOptions()
		{
			throw null;
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
			throw null;
		}

		public HttpsRedirectionMiddleware(RequestDelegate next, IOptions<HttpsRedirectionOptions> options, IConfiguration config, ILoggerFactory loggerFactory, IServerAddressesFeature serverAddressesFeature)
		{
			throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public HttpsRedirectionOptions()
		{
			throw null;
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
		{
			throw null;
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
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public DataProtectionTokenProviderOptions()
		{
			throw null;
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

		public string Name
		{
			get
			{
				throw null;
			}
		}

		public ILogger<DataProtectorTokenProvider<TUser>> Logger
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DataProtectorTokenProvider(IDataProtectionProvider dataProtectionProvider, IOptions<DataProtectionTokenProviderOptions> options, ILogger<DataProtectorTokenProvider<TUser>> logger)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(DataProtectorTokenProvider<>._003CGenerateAsync_003Ed__14))]
		[DebuggerStepThrough]
		public virtual Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(DataProtectorTokenProvider<>._003CValidateAsync_003Ed__15))]
		[DebuggerStepThrough]
		public virtual Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
		{
			throw null;
		}

		public virtual Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public ExternalLoginInfo(ClaimsPrincipal principal, string loginProvider, string providerKey, string displayName)
		{
			throw null;
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

		public IdentityConstants()
		{
			throw null;
		}
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
		public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder)
		{
			throw null;
		}

		public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder, Action<IdentityCookiesBuilder> configureCookies)
		{
			throw null;
		}

		public static OptionsBuilder<CookieAuthenticationOptions> AddApplicationCookie(this AuthenticationBuilder builder)
		{
			throw null;
		}

		public static OptionsBuilder<CookieAuthenticationOptions> AddExternalCookie(this AuthenticationBuilder builder)
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public IdentityCookiesBuilder()
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public SecurityStampRefreshingPrincipalContext()
		{
			throw null;
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
	public class SecurityStampValidator<TUser> : ISecurityStampValidator where TUser : class
	{
		public SignInManager<TUser> SignInManager
		{
			[CompilerGenerated]
			get
			{
				throw null;
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
				throw null;
			}
		}

		public SecurityStampValidator(IOptions<SecurityStampValidatorOptions> options, SignInManager<TUser> signInManager, ISystemClock clock, ILoggerFactory logger)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(SecurityStampValidator<>._003CSecurityStampVerified_003Ed__14))]
		[DebuggerStepThrough]
		protected virtual Task SecurityStampVerified(TUser user, CookieValidatePrincipalContext context)
		{
			throw null;
		}

		protected virtual Task<TUser> VerifySecurityStamp(ClaimsPrincipal principal)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(SecurityStampValidator<>._003CValidateAsync_003Ed__16))]
		[DebuggerStepThrough]
		public virtual Task ValidateAsync(CookieValidatePrincipalContext context)
		{
			throw null;
		}
	}
	public static class SecurityStampValidator
	{
		public static Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
		{
			throw null;
		}

		public static Task ValidateAsync<TValidator>(CookieValidatePrincipalContext context) where TValidator : ISecurityStampValidator
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public SecurityStampValidatorOptions()
		{
			throw null;
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
	public class TwoFactorSecurityStampValidator<TUser> : SecurityStampValidator<TUser>, ITwoFactorSecurityStampValidator, ISecurityStampValidator where TUser : class
	{
		public TwoFactorSecurityStampValidator(IOptions<SecurityStampValidatorOptions> options, SignInManager<TUser> signInManager, ISystemClock clock, ILoggerFactory logger)
		{
			throw null;
		}

		protected override Task<TUser> VerifySecurityStamp(ClaimsPrincipal principal)
		{
			throw null;
		}

		protected override Task SecurityStampVerified(TUser user, CookieValidatePrincipalContext context)
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public bool ApplyCurrentCultureToResponseHeaders
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public RequestLocalizationOptions()
		{
			throw null;
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
				throw null;
			}
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}

		public AcceptLanguageHeaderRequestCultureProvider()
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
				throw null;
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

		public CookieRequestCultureProvider()
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
			throw null;
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
		RequestCulture RequestCulture
		{
			get;
		}

		IRequestCultureProvider Provider
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
			throw null;
		}

		public ProviderCultureResult(StringSegment culture, StringSegment uiCulture)
		{
			throw null;
		}

		public ProviderCultureResult(IList<StringSegment> cultures)
		{
			throw null;
		}

		public ProviderCultureResult(IList<StringSegment> cultures, IList<StringSegment> uiCultures)
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}

		public QueryStringRequestCultureProvider()
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
			throw null;
		}

		public RequestCulture(string culture)
		{
			throw null;
		}

		public RequestCulture(string culture, string uiCulture)
		{
			throw null;
		}

		public RequestCulture(CultureInfo culture, CultureInfo uiCulture)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\RequestCultureFeature.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Localization
{
	public class RequestCultureFeature : IRequestCultureFeature
	{
		public RequestCulture RequestCulture
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IRequestCultureProvider Provider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RequestCultureFeature(RequestCulture requestCulture, IRequestCultureProvider provider)
		{
			throw null;
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
				throw null;
			}
		}

		public abstract Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext);

		protected RequestCultureProvider()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.AspNetCore.Localization\RequestLocalizationMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Localization
{
	public class RequestLocalizationMiddleware
	{
		public RequestLocalizationMiddleware(RequestDelegate next, IOptions<RequestLocalizationOptions> options, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__5))]
		[DebuggerStepThrough]
		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Localization\Microsoft.Extensions.DependencyInjection\RequestLocalizationServiceCollectionExtensions.cs
using Microsoft.AspNetCore.Builder;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class RequestLocalizationServiceCollectionExtensions
	{
		public static IServiceCollection AddRequestLocalization(this IServiceCollection services, Action<RequestLocalizationOptions> configureOptions)
		{
			throw null;
		}

		public static IServiceCollection AddRequestLocalization<TService>(this IServiceCollection services, Action<RequestLocalizationOptions, TService> configureOptions) where TService : class
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
				throw null;
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
				throw null;
			}
		}

		public override Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
		{
			throw null;
		}

		public RouteDataRequestCultureProvider()
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
		string? Policy
		{
			get;
			set;
		}

		string? Roles
		{
			get;
			set;
		}

		string? AuthenticationSchemes
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
		public static IEndpointConventionBuilder MapGet(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
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

		public static IEndpointConventionBuilder MapDelete(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapMethods(this IEndpointRouteBuilder endpoints, string pattern, IEnumerable<string> httpMethods, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder Map(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
		{
			throw null;
		}

		public static IEndpointConventionBuilder Map(this IEndpointRouteBuilder endpoints, RoutePattern pattern, RequestDelegate requestDelegate)
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
		public static IApplicationBuilder UseRouting(this IApplicationBuilder builder)
		{
			throw null;
		}

		public static IApplicationBuilder UseEndpoints(this IApplicationBuilder builder, Action<IEndpointRouteBuilder> configure)
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
		private class BackCompatInlineConstraintResolver : IInlineConstraintResolver
		{
			public BackCompatInlineConstraintResolver(IInlineConstraintResolver inner, ParameterPolicyFactory parameterPolicyFactory)
			{
				throw null;
			}

			public IRouteConstraint? ResolveConstraint(string inlineConstraint)
			{
				throw null;
			}
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string? name, string? template)
		{
			throw null;
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string? name, string? template, object? defaults)
		{
			throw null;
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string? name, string? template, object? defaults, object? constraints)
		{
			throw null;
		}

		public static IRouteBuilder MapRoute(this IRouteBuilder routeBuilder, string? name, string? template, object? defaults, object? constraints, object? dataTokens)
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder
{
	public class RouterMiddleware
	{
		public RouterMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IRouter router)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__4))]
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

		public static TBuilder WithDisplayName<TBuilder>(this TBuilder builder, string displayName) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder WithDisplayName<TBuilder>(this TBuilder builder, Func<EndpointBuilder, string> func) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}

		public static TBuilder WithMetadata<TBuilder>(this TBuilder builder, params object[] items) where TBuilder : IEndpointConventionBuilder
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\ArrayBuilder.cs
namespace Microsoft.AspNetCore.Routing
{
	internal struct ArrayBuilder<T>
	{
		private const int DefaultCapacity = 4;

		private const int MaxCoreClrArrayLength = 2146435071;

		private T[] _array;

		private int _count;

		public int Capacity
		{
			get
			{
				throw null;
			}
		}

		public T[] Buffer
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

		public ArrayBuilder(int capacity)
		{
			throw null;
		}

		public void Add(T item)
		{
			throw null;
		}

		public T First()
		{
			throw null;
		}

		public T Last()
		{
			throw null;
		}

		public T[] ToArray()
		{
			throw null;
		}

		public void UncheckedAdd(T item)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\CompositeEndpointDataSource.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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

		internal CompositeEndpointDataSource(ObservableCollection<EndpointDataSource> dataSources)
		{
			throw null;
		}

		public CompositeEndpointDataSource(IEnumerable<EndpointDataSource> endpointDataSources)
		{
			throw null;
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
			throw null;
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
			throw null;
		}

		public DefaultEndpointDataSource(IEnumerable<Endpoint> endpoints)
		{
			throw null;
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
			throw null;
		}

		public virtual IRouteConstraint? ResolveConstraint(string inlineConstraint)
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

		protected EndpointDataSource()
		{
			throw null;
		}
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
			throw null;
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
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
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
			throw null;
		}

		public HostAttribute(params string[] hosts)
		{
			throw null;
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
			throw null;
		}

		public HttpMethodMetadata(IEnumerable<string> httpMethods, bool acceptCorsPreflight)
		{
			throw null;
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
		IServiceProvider ServiceProvider
		{
			get;
		}

		ICollection<EndpointDataSource> DataSources
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
		IRouteConstraint? ResolveConstraint(string inlineConstraint);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\INamedRouter.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface INamedRouter : IRouter
	{
		string? Name
		{
			get;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\InlineRouteParameterParser.cs
using Microsoft.AspNetCore.Routing.Template;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public static class InlineRouteParameterParser
	{
		private enum ParseState
		{
			Start,
			ParsingName,
			InsideParenthesis,
			End
		}

		private readonly struct ConstraintParseResults
		{
			public readonly int CurrentIndex;

			public readonly IEnumerable<InlineConstraint> Constraints;

			public ConstraintParseResults(int currentIndex, IEnumerable<InlineConstraint> constraints)
			{
				throw null;
			}
		}

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
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public interface IRouteBuilder
	{
		IApplicationBuilder ApplicationBuilder
		{
			get;
		}

		IRouter? DefaultHandler
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get;
			[System.Runtime.CompilerServices.NullableContext(2)]
			set;
		}

		IServiceProvider ServiceProvider
		{
			get;
		}

		IList<IRouter> Routes
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
		public static string? GetPathByName(this LinkGenerator generator, HttpContext httpContext, string endpointName, object? values, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions? options = null)
		{
			throw null;
		}

		public static string? GetPathByName(this LinkGenerator generator, string endpointName, object? values, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions? options = null)
		{
			throw null;
		}

		public static string? GetUriByName(this LinkGenerator generator, HttpContext httpContext, string endpointName, object? values, string? scheme = null, HostString? host = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions? options = null)
		{
			throw null;
		}

		public static string? GetUriByName(this LinkGenerator generator, string endpointName, object? values, string scheme, HostString host, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions? options = null)
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
		public static string? GetPathByRouteValues(this LinkGenerator generator, HttpContext httpContext, string? routeName, object? values, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions? options = null)
		{
			throw null;
		}

		public static string? GetPathByRouteValues(this LinkGenerator generator, string? routeName, object? values, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions? options = null)
		{
			throw null;
		}

		public static string? GetUriByRouteValues(this LinkGenerator generator, HttpContext httpContext, string? routeName, object? values, string? scheme = null, HostString? host = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions? options = null)
		{
			throw null;
		}

		public static string? GetUriByRouteValues(this LinkGenerator generator, string? routeName, object? values, string scheme, HostString host, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions? options = null)
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
		public abstract RouteValueDictionary? ParsePathByAddress<TAddress>(TAddress address, PathString path);

		protected LinkParser()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\LinkParserEndpointNameAddressExtensions.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing
{
	public static class LinkParserEndpointNameAddressExtensions
	{
		public static RouteValueDictionary? ParsePathByEndpointName(this LinkParser parser, string endpointName, PathString path)
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

		protected MatcherPolicy()
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
		public abstract IParameterPolicy Create(RoutePatternParameterPart? parameter, string inlineText);

		public abstract IParameterPolicy Create(RoutePatternParameterPart? parameter, IParameterPolicy parameterPolicy);

		public IParameterPolicy Create(RoutePatternParameterPart? parameter, RoutePatternParameterPolicyReference reference)
		{
			throw null;
		}

		protected ParameterPolicyFactory()
		{
			throw null;
		}
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
	internal struct PathTokenizer : IReadOnlyList<StringSegment>, IEnumerable<StringSegment>, IEnumerable, IReadOnlyCollection<StringSegment>
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
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Reset()
			{
				throw null;
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
		public static IRouteBuilder MapRoute(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewareRoute(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapDelete(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewareDelete(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
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

		public static IRouteBuilder MapMiddlewareGet(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapGet(this IRouteBuilder builder, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}

		public static IRouteBuilder MapPost(this IRouteBuilder builder, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewarePost(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
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

		public static IRouteBuilder MapMiddlewarePut(this IRouteBuilder builder, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}

		public static IRouteBuilder MapPut(this IRouteBuilder builder, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}

		public static IRouteBuilder MapVerb(this IRouteBuilder builder, string verb, string template, Func<HttpRequest, HttpResponse, RouteData, Task> handler)
		{
			throw null;
		}

		public static IRouteBuilder MapVerb(this IRouteBuilder builder, string verb, string template, RequestDelegate handler)
		{
			throw null;
		}

		public static IRouteBuilder MapMiddlewareVerb(this IRouteBuilder builder, string verb, string template, Action<IApplicationBuilder> action)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\Route.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public class Route : RouteBase
	{
		public string? RouteTemplate
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
		}

		public Route(IRouter target, string routeTemplate, IInlineConstraintResolver inlineConstraintResolver)
		{
			throw null;
		}

		public Route(IRouter target, string routeTemplate, RouteValueDictionary? defaults, IDictionary<string, object>? constraints, RouteValueDictionary? dataTokens, IInlineConstraintResolver inlineConstraintResolver)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(2)]
		public Route(IRouter target, string? routeName, string? routeTemplate, RouteValueDictionary? defaults, IDictionary<string, object>? constraints, RouteValueDictionary? dataTokens, IInlineConstraintResolver inlineConstraintResolver)
		{
			throw null;
		}

		protected override Task OnRouteMatched(RouteContext context)
		{
			throw null;
		}

		protected override VirtualPathData? OnVirtualPathGenerated(VirtualPathContext context)
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
	public abstract class RouteBase : IRouter, INamedRouter
	{
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public virtual string? Name
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			protected set
			{
				throw null;
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
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(2)]
		public RouteBase(string? template, string? name, IInlineConstraintResolver constraintResolver, RouteValueDictionary? defaults, IDictionary<string, object>? constraints, RouteValueDictionary? dataTokens)
		{
			throw null;
		}

		protected abstract Task OnRouteMatched(RouteContext context);

		protected abstract VirtualPathData? OnVirtualPathGenerated(VirtualPathContext context);

		public virtual Task RouteAsync(RouteContext context)
		{
			throw null;
		}

		public virtual VirtualPathData? GetVirtualPath(VirtualPathContext context)
		{
			throw null;
		}

		protected static IDictionary<string, IRouteConstraint> GetConstraints(IInlineConstraintResolver inlineConstraintResolver, RouteTemplate parsedTemplate, IDictionary<string, object>? constraints)
		{
			throw null;
		}

		protected static RouteValueDictionary GetDefaults(RouteTemplate parsedTemplate, RouteValueDictionary? defaults)
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

		public IRouter? DefaultHandler
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
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

		public IList<IRouter> Routes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RouteBuilder(IApplicationBuilder applicationBuilder)
		{
			throw null;
		}

		public RouteBuilder(IApplicationBuilder applicationBuilder, IRouter? defaultHandler)
		{
			throw null;
		}

		public IRouter Build()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteCollection.cs
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteCollection : IRouteCollection, IRouter
	{
		public IRouter this[int index]
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

		public void Add(IRouter router)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CRouteAsync_003Ed__10))]
		[DebuggerStepThrough]
		public virtual Task RouteAsync(RouteContext context)
		{
			throw null;
		}

		public virtual VirtualPathData? GetVirtualPath(VirtualPathContext context)
		{
			throw null;
		}

		public RouteCollection()
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
			throw null;
		}

		public IDictionary<string, IRouteConstraint> Build()
		{
			throw null;
		}

		public void AddConstraint(string key, object value)
		{
			throw null;
		}

		public void AddResolvedConstraint(string key, string constraintText)
		{
			throw null;
		}

		public void SetOptional(string key)
		{
			throw null;
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
			throw null;
		}

		public RouteCreationException(string message, Exception innerException)
		{
			throw null;
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

		public RouteEndpoint(RequestDelegate requestDelegate, RoutePattern routePattern, int order, EndpointMetadataCollection? metadata, string? displayName)
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public RouteEndpointBuilder(RequestDelegate requestDelegate, RoutePattern routePattern, int order)
		{
			throw null;
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
			throw null;
		}

		public RequestDelegate GetRequestHandler(HttpContext httpContext, RouteData routeData)
		{
			throw null;
		}

		public VirtualPathData? GetVirtualPath(VirtualPathContext context)
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
			throw null;
		}

		internal string DebuggerToString()
		{
			throw null;
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
		internal ICollection<EndpointDataSource> EndpointDataSources
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public RouteOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RouteValueEqualityComparer.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing
{
	public class RouteValueEqualityComparer : IEqualityComparer<object?>
	{
		public static readonly RouteValueEqualityComparer Default;

		public new bool Equals(object? x, object? y)
		{
			throw null;
		}

		public int GetHashCode(object obj)
		{
			throw null;
		}

		public RouteValueEqualityComparer()
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
		public string? RouteName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public RouteValueDictionary ExplicitValues
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public RouteValueDictionary? AmbientValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public RouteValuesAddress()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\RoutingFeature.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class RoutingFeature : IRoutingFeature
	{
		public RouteData? RouteData
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public RoutingFeature()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing\SegmentState.cs
namespace Microsoft.AspNetCore.Routing
{
	internal enum SegmentState
	{
		Beginning,
		Inside
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

		public SuppressLinkGenerationMetadata()
		{
			throw null;
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

		public SuppressMatchingMetadata()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\AlphaRouteConstraint.cs
namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class AlphaRouteConstraint : RegexRouteConstraint
	{
		public AlphaRouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\BoolRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class BoolRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public BoolRouteConstraint()
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
	public class CompositeRouteConstraint : IRouteConstraint, IParameterPolicy
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
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\DateTimeRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class DateTimeRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public DateTimeRouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\DecimalRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class DecimalRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public DecimalRouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\DoubleRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class DoubleRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public DoubleRouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\FileNameRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class FileNameRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		internal static bool IsFileName(ReadOnlySpan<char> value)
		{
			throw null;
		}

		public FileNameRouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\FloatRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class FloatRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public FloatRouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\GuidRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class GuidRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public GuidRouteConstraint()
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
	public class HttpMethodRouteConstraint : IRouteConstraint, IParameterPolicy
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
			throw null;
		}

		public virtual bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\IntRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class IntRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public IntRouteConstraint()
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
	public class LengthRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public int MinLength
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int MaxLength
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LengthRouteConstraint(int length)
		{
			throw null;
		}

		public LengthRouteConstraint(int minLength, int maxLength)
		{
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\LongRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class LongRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public LongRouteConstraint()
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
	public class MaxLengthRouteConstraint : IRouteConstraint, IParameterPolicy
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
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
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
	public class MaxRouteConstraint : IRouteConstraint, IParameterPolicy
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
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
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
	public class MinLengthRouteConstraint : IRouteConstraint, IParameterPolicy
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
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
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
	public class MinRouteConstraint : IRouteConstraint, IParameterPolicy
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
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\NonFileNameRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class NonFileNameRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public NonFileNameRouteConstraint()
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
	public class OptionalRouteConstraint : IRouteConstraint, IParameterPolicy
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
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
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
	public class RangeRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public long Min
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public long Max
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RangeRouteConstraint(long min, long max)
		{
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\RegexInlineRouteConstraint.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class RegexInlineRouteConstraint : RegexRouteConstraint
	{
		[System.Runtime.CompilerServices.NullableContext(1)]
		public RegexInlineRouteConstraint(string regexPattern)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\RegexRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class RegexRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public Regex Constraint
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public RegexRouteConstraint(Regex regex)
		{
			throw null;
		}

		public RegexRouteConstraint(string regexPattern)
		{
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\RequiredRouteConstraint.cs
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class RequiredRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
		{
			throw null;
		}

		public RequiredRouteConstraint()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Constraints\StringRouteConstraint.cs
using Microsoft.AspNetCore.Http;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Constraints
{
	public class StringRouteConstraint : IRouteConstraint, IParameterPolicy
	{
		[System.Runtime.CompilerServices.NullableContext(1)]
		public StringRouteConstraint(string value)
		{
			throw null;
		}

		public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection)
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
			throw null;
		}

		public void Write(EndpointDataSource dataSource, TextWriter writer)
		{
			throw null;
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

		public Candidate(Endpoint endpoint, int score, KeyValuePair<string, object>[] slots, (string parameterName, int segmentIndex, int slotIndex)[] captures, in (string parameterName, int segmentIndex, int slotIndex) catchAll, (RoutePatternPathSegment pathSegment, int segmentIndex)[] complexSegments, KeyValuePair<string, IRouteConstraint>[] constraints)
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
			throw null;
		}

		internal CandidateSet(Candidate[] candidates)
		{
			throw null;
		}

		internal CandidateSet(CandidateState[] candidates)
		{
			throw null;
		}

		public bool IsValidCandidate(int index)
		{
			throw null;
		}

		internal static bool IsValidCandidate(ref CandidateState candidate)
		{
			throw null;
		}

		public void SetValidity(int index, bool value)
		{
			throw null;
		}

		internal static void SetValidity(ref CandidateState candidate, bool value)
		{
			throw null;
		}

		public void ReplaceEndpoint(int index, Endpoint? endpoint, RouteValueDictionary? values)
		{
			throw null;
		}

		public void ExpandEndpoint(int index, IReadOnlyList<Endpoint> endpoints, IComparer<Endpoint> comparer)
		{
			throw null;
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
		public Endpoint Endpoint
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public int Score
		{
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
		}

		public RouteValueDictionary? Values
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			readonly get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			internal set
			{
				throw null;
			}
		}

		internal CandidateState(Endpoint endpoint, int score)
		{
			throw null;
		}

		internal CandidateState(Endpoint endpoint, RouteValueDictionary? values, int score)
		{
			throw null;
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
		internal EndpointMetadataComparer(IServiceProvider services)
		{
			throw null;
		}

		int IComparer<Endpoint>.Compare(Endpoint? x, Endpoint? y)
		{
			throw null;
		}
	}
	public abstract class EndpointMetadataComparer<TMetadata> : IComparer<Endpoint> where TMetadata : class
	{
		private class DefaultComparer<T> : EndpointMetadataComparer<T> where T : class
		{
			public DefaultComparer()
			{
				throw null;
			}
		}

		public static readonly EndpointMetadataComparer<TMetadata> Default;

		public int Compare(Endpoint? x, Endpoint? y)
		{
			throw null;
		}

		protected virtual TMetadata? GetMetadata(Endpoint endpoint)
		{
			throw null;
		}

		protected virtual int CompareMetadata(TMetadata? x, TMetadata? y)
		{
			throw null;
		}

		protected EndpointMetadataComparer()
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

		protected EndpointSelector()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\HostMatcherPolicy.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public sealed class HostMatcherPolicy : MatcherPolicy, IEndpointComparerPolicy, INodeBuilderPolicy, IEndpointSelectorPolicy
	{
		private class HostMetadataEndpointComparer : EndpointMetadataComparer<IHostMetadata>
		{
			protected override int CompareMetadata(IHostMetadata? x, IHostMetadata? y)
			{
				throw null;
			}

			public HostMetadataEndpointComparer()
			{
				throw null;
			}
		}

		private class HostPolicyJumpTable : PolicyJumpTable
		{
			public HostPolicyJumpTable(int exitDestination, (EdgeKey host, int destination)[] destinations)
			{
				throw null;
			}

			public override int GetDestination(HttpContext httpContext)
			{
				throw null;
			}
		}

		private readonly struct EdgeKey : IEquatable<EdgeKey>, IComparable<EdgeKey>, IComparable
		{
			internal static readonly EdgeKey WildcardEdgeKey;

			public readonly int? Port;

			public readonly string Host;

			private readonly string? _wildcardEndsWith;

			public bool HasHostWildcard
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public bool MatchesHost
			{
				get
				{
					throw null;
				}
			}

			public bool MatchesPort
			{
				get
				{
					throw null;
				}
			}

			public bool MatchesAll
			{
				get
				{
					throw null;
				}
			}

			[System.Runtime.CompilerServices.NullableContext(2)]
			public EdgeKey(string? host, int? port)
			{
				throw null;
			}

			public int CompareTo(EdgeKey other)
			{
				throw null;
			}

			public int CompareTo(object? obj)
			{
				throw null;
			}

			public bool Equals(EdgeKey other)
			{
				throw null;
			}

			public bool MatchHost(string host)
			{
				throw null;
			}

			public override int GetHashCode()
			{
				throw null;
			}

			public override bool Equals(object? obj)
			{
				throw null;
			}

			public override string ToString()
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

		public IComparer<Endpoint> Comparer
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		bool INodeBuilderPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		bool IEndpointSelectorPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
		{
			throw null;
		}

		public IReadOnlyList<PolicyNodeEdge> GetEdges(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		public PolicyJumpTable BuildJumpTable(int exitDestination, IReadOnlyList<PolicyJumpTableEdge> edges)
		{
			throw null;
		}

		public HostMatcherPolicy()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\HttpMethodMatcherPolicy.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public sealed class HttpMethodMatcherPolicy : MatcherPolicy, IEndpointComparerPolicy, INodeBuilderPolicy, IEndpointSelectorPolicy
	{
		private class HttpMethodPolicyJumpTable : PolicyJumpTable
		{
			public HttpMethodPolicyJumpTable(int exitDestination, Dictionary<string, int>? destinations, int corsPreflightExitDestination, Dictionary<string, int>? corsPreflightDestinations)
			{
				throw null;
			}

			public override int GetDestination(HttpContext httpContext)
			{
				throw null;
			}
		}

		private class HttpMethodMetadataEndpointComparer : EndpointMetadataComparer<IHttpMethodMetadata>
		{
			protected override int CompareMetadata(IHttpMethodMetadata? x, IHttpMethodMetadata? y)
			{
				throw null;
			}

			public HttpMethodMetadataEndpointComparer()
			{
				throw null;
			}
		}

		internal readonly struct EdgeKey : IEquatable<EdgeKey>, IComparable<EdgeKey>, IComparable
		{
			public readonly bool IsCorsPreflightRequest;

			public readonly string HttpMethod;

			[System.Runtime.CompilerServices.NullableContext(1)]
			public EdgeKey(string httpMethod, bool isCorsPreflightRequest)
			{
				throw null;
			}

			public int CompareTo(EdgeKey other)
			{
				throw null;
			}

			public int CompareTo(object? obj)
			{
				throw null;
			}

			public bool Equals(EdgeKey other)
			{
				throw null;
			}

			public override bool Equals(object? obj)
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

		internal static readonly string OriginHeader;

		internal static readonly string AccessControlRequestMethod;

		internal static readonly string PreflightHttpMethod;

		internal const string Http405EndpointDisplayName = "405 HTTP Method Not Supported";

		internal const string AnyMethod = "*";

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

		bool INodeBuilderPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		bool IEndpointSelectorPolicy.AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
		{
			throw null;
		}

		public IReadOnlyList<PolicyNodeEdge> GetEdges(IReadOnlyList<Endpoint> endpoints)
		{
			throw null;
		}

		public PolicyJumpTable BuildJumpTable(int exitDestination, IReadOnlyList<PolicyJumpTableEdge> edges)
		{
			throw null;
		}

		public HttpMethodMatcherPolicy()
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

		IReadOnlyList<PolicyNodeEdge> GetEdges(IReadOnlyList<Endpoint> endpoints);

		PolicyJumpTable BuildJumpTable(int exitDestination, IReadOnlyList<PolicyJumpTableEdge> edges);
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\JumpTable.cs
using System.Diagnostics;

namespace Microsoft.AspNetCore.Routing.Matching
{
	[DebuggerDisplay("{DebuggerToString(),nq}")]
	internal abstract class JumpTable
	{
		public abstract int GetDestination(string path, PathSegment segment);

		public virtual string DebuggerToString()
		{
			throw null;
		}

		protected JumpTable()
		{
			throw null;
		}
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

		protected Matcher()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\MatcherBuilder.cs
namespace Microsoft.AspNetCore.Routing.Matching
{
	internal abstract class MatcherBuilder
	{
		public abstract void AddEndpoint(RouteEndpoint endpoint);

		public abstract Matcher Build();

		protected MatcherBuilder()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\MatcherFactory.cs
namespace Microsoft.AspNetCore.Routing.Matching
{
	internal abstract class MatcherFactory
	{
		public abstract Matcher CreateMatcher(EndpointDataSource dataSource);

		protected MatcherFactory()
		{
			throw null;
		}
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

		public override bool Equals(object? obj)
		{
			throw null;
		}

		public bool Equals(PathSegment other)
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

		internal virtual string DebuggerToString()
		{
			throw null;
		}

		protected PolicyJumpTable()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Matching\PolicyJumpTableEdge.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Matching
{
	public readonly struct PolicyJumpTableEdge
	{
		public object State
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public int Destination
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
		[DebuggerDisplay("{DebuggerToString(),nq}")]
		private class RequiredValueAnySentinal
		{
			public RequiredValueAnySentinal()
			{
				throw null;
			}
		}

		public static readonly object RequiredValueAny;

		public IReadOnlyDictionary<string, object?> Defaults
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

		public IReadOnlyDictionary<string, object?> RequiredValues
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

		public string? RawText
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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

		internal static bool IsRequiredValueAny(object? value)
		{
			throw null;
		}

		internal RoutePattern(string? rawText, IReadOnlyDictionary<string, object?> defaults, IReadOnlyDictionary<string, IReadOnlyList<RoutePatternParameterPolicyReference>> parameterPolicies, IReadOnlyDictionary<string, object?> requiredValues, IReadOnlyList<RoutePatternParameterPart> parameters, IReadOnlyList<RoutePatternPathSegment> pathSegments)
		{
			throw null;
		}

		public RoutePatternParameterPart? GetParameter(string name)
		{
			throw null;
		}

		internal string DebuggerToString()
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
	[Serializable]
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
			throw null;
		}

		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternFactory.cs
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	public static class RoutePatternFactory
	{
		public static RoutePattern Parse(string pattern)
		{
			throw null;
		}

		public static RoutePattern Parse(string pattern, object? defaults, object? parameterPolicies)
		{
			throw null;
		}

		public static RoutePattern Parse(string pattern, object? defaults, object? parameterPolicies, object? requiredValues)
		{
			throw null;
		}

		public static RoutePattern Pattern(IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string? rawText, IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(object? defaults, object? parameterPolicies, IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string? rawText, object? defaults, object? parameterPolicies, IEnumerable<RoutePatternPathSegment> segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string rawText, params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(object? defaults, object? parameterPolicies, params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePattern Pattern(string? rawText, object? defaults, object? parameterPolicies, params RoutePatternPathSegment[] segments)
		{
			throw null;
		}

		public static RoutePatternPathSegment Segment(IEnumerable<RoutePatternPart> parts)
		{
			throw null;
		}

		public static RoutePatternPathSegment Segment(params RoutePatternPart[] parts)
		{
			throw null;
		}

		public static RoutePatternLiteralPart LiteralPart(string content)
		{
			throw null;
		}

		public static RoutePatternSeparatorPart SeparatorPart(string content)
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

		public static RoutePatternParameterPart ParameterPart(string parameterName, object? @default, RoutePatternParameterKind parameterKind)
		{
			throw null;
		}

		public static RoutePatternParameterPart ParameterPart(string parameterName, object? @default, RoutePatternParameterKind parameterKind, IEnumerable<RoutePatternParameterPolicyReference> parameterPolicies)
		{
			throw null;
		}

		public static RoutePatternParameterPart ParameterPart(string parameterName, object? @default, RoutePatternParameterKind parameterKind, params RoutePatternParameterPolicyReference[] parameterPolicies)
		{
			throw null;
		}

		public static RoutePatternParameterPolicyReference Constraint(object constraint)
		{
			throw null;
		}

		public static RoutePatternParameterPolicyReference Constraint(IRouteConstraint constraint)
		{
			throw null;
		}

		public static RoutePatternParameterPolicyReference Constraint(string constraint)
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

		internal RoutePatternLiteralPart(string content)
		{
			throw null;
		}

		internal override string DebuggerToString()
		{
			throw null;
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
		public IReadOnlyList<RoutePatternParameterPolicyReference> ParameterPolicies
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

		public object? Default
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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

		public RoutePatternParameterKind ParameterKind
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

		internal RoutePatternParameterPart(string parameterName, object? @default, RoutePatternParameterKind parameterKind, RoutePatternParameterPolicyReference[] parameterPolicies)
		{
			throw null;
		}

		internal RoutePatternParameterPart(string parameterName, object? @default, RoutePatternParameterKind parameterKind, RoutePatternParameterPolicyReference[] parameterPolicies, bool encodeSlashes)
		{
			throw null;
		}

		internal override string DebuggerToString()
		{
			throw null;
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
		public string? Content
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IParameterPolicy? ParameterPolicy
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		internal RoutePatternParameterPolicyReference(string content)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		internal RoutePatternParameterPolicyReference(IParameterPolicy parameterPolicy)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternPart.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Patterns
{
	public abstract class RoutePatternPart
	{
		public RoutePatternPartKind PartKind
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

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

		private protected RoutePatternPart(RoutePatternPartKind partKind)
		{
			throw null;
		}

		internal abstract string DebuggerToString();
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

		internal RoutePatternPathSegment(IReadOnlyList<RoutePatternPart> parts)
		{
			throw null;
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

		internal RoutePatternSeparatorPart(string content)
		{
			throw null;
		}

		internal override string DebuggerToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Patterns\RoutePatternTransformer.cs
namespace Microsoft.AspNetCore.Routing.Patterns
{
	public abstract class RoutePatternTransformer
	{
		public abstract RoutePattern? SubstituteRequiredValues(RoutePattern original, object requiredValues);

		protected RoutePatternTransformer()
		{
			throw null;
		}
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

		public InlineConstraint(string constraint)
		{
			throw null;
		}

		public InlineConstraint(RoutePatternParameterPolicyReference other)
		{
			throw null;
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

		internal static decimal ComputeInbound(RoutePattern routePattern)
		{
			throw null;
		}

		public static decimal ComputeOutbound(RouteTemplate template)
		{
			throw null;
		}

		internal static decimal ComputeOutbound(RoutePattern routePattern)
		{
			throw null;
		}

		internal static int ComputeInboundPrecedenceDigit(RoutePattern routePattern, RoutePatternPathSegment pathSegment)
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
		public string? TemplateText
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

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

		public RouteTemplate(RoutePattern other)
		{
			throw null;
		}

		public RouteTemplate(string template, List<TemplateSegment> segments)
		{
			throw null;
		}

		public TemplateSegment? GetSegment(int index)
		{
			throw null;
		}

		public TemplatePart? GetParameter(string name)
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
using System.Diagnostics;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Routing.Template
{
	public class TemplateBinder
	{
		[DebuggerDisplay("explicit null")]
		private class SentinullValue
		{
			public static object Instance;

			public override string ToString()
			{
				throw null;
			}
		}

		internal TemplateBinder(UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> pool, RouteTemplate template, RouteValueDictionary defaults)
		{
			throw null;
		}

		internal TemplateBinder(UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> pool, RoutePattern pattern, RouteValueDictionary? defaults, IEnumerable<string>? requiredKeys, IEnumerable<(string parameterName, IParameterPolicy policy)>? parameterPolicies)
		{
			throw null;
		}

		internal TemplateBinder(UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> pool, RoutePattern pattern, IEnumerable<(string parameterName, IParameterPolicy policy)> parameterPolicies)
		{
			throw null;
		}

		public TemplateValuesResult? GetValues(RouteValueDictionary? ambientValues, RouteValueDictionary values)
		{
			throw null;
		}

		public bool TryProcessConstraints(HttpContext? httpContext, RouteValueDictionary combinedValues, out string? parameterName, out IRouteConstraint? constraint)
		{
			throw null;
		}

		public string? BindValues(RouteValueDictionary acceptedValues)
		{
			throw null;
		}

		internal bool TryBindValues(RouteValueDictionary acceptedValues, LinkOptions? options, LinkOptions globalOptions, out (PathString path, QueryString query) result)
		{
			throw null;
		}

		public static bool RoutePartsEqual(object? a, object? b)
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
		public abstract TemplateBinder Create(RouteTemplate template, RouteValueDictionary defaults);

		public abstract TemplateBinder Create(RoutePattern pattern);

		protected TemplateBinderFactory()
		{
			throw null;
		}
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
			throw null;
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

		public bool IsParameter
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
				throw null;
			}
		}

		public string? Name
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? Text
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object? DefaultValue
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IEnumerable<InlineConstraint> InlineConstraints
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public TemplatePart()
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public TemplatePart(RoutePatternPart other)
		{
			throw null;
		}

		public static TemplatePart CreateLiteral(string text)
		{
			throw null;
		}

		public static TemplatePart CreateParameter(string name, bool isCatchAll, bool isOptional, object? defaultValue, IEnumerable<InlineConstraint>? inlineConstraints)
		{
			throw null;
		}

		internal string? DebuggerToString()
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
			throw null;
		}

		public TemplateSegment(RoutePatternPathSegment other)
		{
			throw null;
		}

		internal string DebuggerToString()
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public TemplateValuesResult()
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public InboundMatch()
		{
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public InboundRouteEntry()
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public OutboundMatch()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\OutboundMatchResult.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	internal readonly struct OutboundMatchResult
	{
		public OutboundMatch Match
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool IsFallbackMatch
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
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
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
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public OutboundRouteEntry()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing\Microsoft.AspNetCore.Routing.Tree\TreeEnumerator.cs
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing.Tree
{
	internal struct TreeEnumerator : IEnumerator<UrlMatchingNode>, IEnumerator, IDisposable
	{
		private readonly Stack<UrlMatchingNode> _stack;

		private readonly PathTokenizer _tokenizer;

		public UrlMatchingNode Current
		{
			[CompilerGenerated]
			readonly get
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

		public TreeEnumerator(UrlMatchingNode root, PathTokenizer tokenizer)
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}

		public bool MoveNext()
		{
			throw null;
		}

		public void Reset()
		{
			throw null;
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

		internal TreeRouteBuilder(ILoggerFactory loggerFactory, ObjectPool<UriBuildingContext> objectPool, IInlineConstraintResolver constraintResolver)
		{
			throw null;
		}

		public InboundRouteEntry MapInbound(IRouter handler, RouteTemplate routeTemplate, string routeName, int order)
		{
			throw null;
		}

		public OutboundRouteEntry MapOutbound(IRouter handler, RouteTemplate routeTemplate, RouteValueDictionary requiredLinkValues, string routeName, int order)
		{
			throw null;
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
			throw null;
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

		internal TreeRouter(UrlMatchingTree[] trees, IEnumerable<OutboundRouteEntry> linkGenerationEntries, UrlEncoder urlEncoder, ObjectPool<UriBuildingContext> objectPool, ILogger routeLogger, ILogger constraintLogger, int version)
		{
			throw null;
		}

		public VirtualPathData GetVirtualPath(VirtualPathContext context)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CRouteAsync_003Ed__13))]
		[DebuggerStepThrough]
		public Task RouteAsync(RouteContext context)
		{
			throw null;
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

		public Dictionary<string, UrlMatchingNode> Literals
		{
			[CompilerGenerated]
			get
			{
				throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public UrlMatchingNode(int length)
		{
			throw null;
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
			throw null;
		}

		internal void AddEntry(InboundRouteEntry entry)
		{
			throw null;
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
				throw null;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(IEnumerable e)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static implicit operator int(HashCodeCombiner self)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(int i)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(string? s)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add(object? o)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Add<TValue>(TValue value, IEqualityComparer<TValue> comparer)
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static HashCodeCombiner Start()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IOutboundParameterTransformer.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IOutboundParameterTransformer : IParameterPolicy
	{
		string? TransformOutbound(object? value);
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
		bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values, RouteDirection routeDirection);
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
		Task RouteAsync(RouteContext context);

		VirtualPathData? GetVirtualPath(VirtualPathContext context);
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\IRoutingFeature.cs
namespace Microsoft.AspNetCore.Routing
{
	public interface IRoutingFeature
	{
		RouteData? RouteData
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
		public abstract string? GetPathByAddress<TAddress>(HttpContext httpContext, TAddress address, RouteValueDictionary values, RouteValueDictionary? ambientValues = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions? options = null);

		public abstract string? GetPathByAddress<TAddress>(TAddress address, RouteValueDictionary values, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions? options = null);

		public abstract string? GetUriByAddress<TAddress>(HttpContext httpContext, TAddress address, RouteValueDictionary values, RouteValueDictionary? ambientValues = null, string? scheme = null, HostString? host = null, PathString? pathBase = null, FragmentString fragment = default(FragmentString), LinkOptions? options = null);

		public abstract string? GetUriByAddress<TAddress>(TAddress address, RouteValueDictionary values, string scheme, HostString host, PathString pathBase = default(PathString), FragmentString fragment = default(FragmentString), LinkOptions? options = null);

		protected LinkGenerator()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.Routing.Abstractions\Microsoft.AspNetCore.Routing\LinkOptions.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Routing
{
	public class LinkOptions
	{
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public LinkOptions()
		{
			throw null;
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
		public RequestDelegate? Handler
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
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

		public RouteData RouteData
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public RouteContext(HttpContext httpContext)
		{
			throw null;
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
			private readonly RouteData _routeData;

			private readonly RouteValueDictionary? _dataTokens;

			private readonly IList<IRouter>? _routers;

			private readonly RouteValueDictionary? _values;

			public RouteDataSnapshot(RouteData routeData, RouteValueDictionary? dataTokens, IList<IRouter>? routers, RouteValueDictionary? values)
			{
				throw null;
			}

			public void Restore()
			{
				throw null;
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
			throw null;
		}

		public RouteData(RouteData other)
		{
			throw null;
		}

		public RouteData(RouteValueDictionary values)
		{
			throw null;
		}

		public RouteDataSnapshot PushState(IRouter? router, RouteValueDictionary? values, RouteValueDictionary? dataTokens)
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

		public static object? GetRouteValue(this HttpContext httpContext, string key)
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

		public string? RouteName
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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
				throw null;
			}
		}

		public VirtualPathContext(HttpContext httpContext, RouteValueDictionary ambientValues, RouteValueDictionary values)
		{
			throw null;
		}

		public VirtualPathContext(HttpContext httpContext, RouteValueDictionary ambientValues, RouteValueDictionary values, string? routeName)
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

		public VirtualPathData(IRouter router, string virtualPath)
		{
			throw null;
		}

		public VirtualPathData(IRouter router, string virtualPath, RouteValueDictionary dataTokens)
		{
			throw null;
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
		private class SessionCookieBuilder : CookieBuilder
		{
			public override TimeSpan? Expiration
			{
				get
				{
					throw null;
				}
				set
				{
					throw null;
				}
			}

			public SessionCookieBuilder()
			{
				throw null;
			}
		}

		public CookieBuilder Cookie
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public SessionOptions()
		{
			throw null;
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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Session
{
	public class DistributedSession : ISession
	{
		public bool IsAvailable
		{
			get
			{
				throw null;
			}
		}

		public string Id
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
			throw null;
		}

		public bool TryGetValue(string key, out byte[] value)
		{
			throw null;
		}

		public void Set(string key, byte[] value)
		{
			throw null;
		}

		public void Remove(string key)
		{
			throw null;
		}

		public void Clear()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CLoadAsync_003Ed__30))]
		[DebuggerStepThrough]
		public Task LoadAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CCommitAsync_003Ed__31))]
		[DebuggerStepThrough]
		public Task CommitAsync(CancellationToken cancellationToken = default(CancellationToken))
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
			throw null;
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
				throw null;
			}
		}

		public SessionFeature()
		{
			throw null;
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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Session
{
	public class SessionMiddleware
	{
		private class SessionEstablisher
		{
			public SessionEstablisher(HttpContext context, string cookieValue, SessionOptions options)
			{
				throw null;
			}
		}

		public SessionMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IDataProtectionProvider dataProtectionProvider, ISessionStore sessionStore, IOptions<SessionOptions> options)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvoke_003Ed__8))]
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
	public sealed class HubEndpointConventionBuilder : IHubEndpointConventionBuilder, IEndpointConventionBuilder
	{
		public void Add(Action<EndpointBuilder> convention)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR\Microsoft.AspNetCore.Builder\HubEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.SignalR;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Builder
{
	public static class HubEndpointRouteBuilderExtensions
	{
		public static HubEndpointConventionBuilder MapHub<[DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] THub>(this IEndpointRouteBuilder endpoints, string pattern) where THub : Hub
		{
			throw null;
		}

		public static HubEndpointConventionBuilder MapHub<[DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] THub>(this IEndpointRouteBuilder endpoints, string pattern, Action<HttpConnectionDispatcherOptions> configureOptions) where THub : Hub
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
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;

namespace Microsoft.AspNetCore.SignalR
{
	[Serializable]
	public class HubException : Exception
	{
		public HubException()
		{
			throw null;
		}

		public HubException(string? message)
		{
			throw null;
		}

		public HubException(string? message, Exception? innerException)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public HubException(SerializationInfo info, StreamingContext context)
		{
			throw null;
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
		Type GetReturnType(string invocationId);

		IReadOnlyList<Type> GetParameterTypes(string methodName);

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
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class CancelInvocationMessage : HubInvocationMessage
	{
		[System.Runtime.CompilerServices.NullableContext(1)]
		public CancelInvocationMessage(string invocationId)
		{
			throw null;
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

		public string? Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool AllowReconnect
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public CloseMessage(string? error)
		{
			throw null;
		}

		public CloseMessage(string? error, bool allowReconnect)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\CompletionMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class CompletionMessage : HubInvocationMessage
	{
		public string? Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object? Result
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

		public CompletionMessage(string invocationId, string? error, object? result, bool hasResult)
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

		public static CompletionMessage Empty(string invocationId)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HandshakeProtocol.cs
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public static class HandshakeProtocol
	{
		public static ReadOnlySpan<byte> GetSuccessfulHandshake(IHubProtocol protocol)
		{
			throw null;
		}

		public static void WriteRequestMessage(HandshakeRequestMessage requestMessage, IBufferWriter<byte> output)
		{
			throw null;
		}

		public static void WriteResponseMessage(HandshakeResponseMessage responseMessage, IBufferWriter<byte> output)
		{
			throw null;
		}

		public static bool TryParseResponseMessage(ref ReadOnlySequence<byte> buffer, [NotNullWhen(true)] out HandshakeResponseMessage? responseMessage)
		{
			throw null;
		}

		public static bool TryParseRequestMessage(ref ReadOnlySequence<byte> buffer, [NotNullWhen(true)] out HandshakeRequestMessage? requestMessage)
		{
			throw null;
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
			throw null;
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

		public string? Error
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HandshakeResponseMessage(string? error)
		{
			throw null;
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
		public IDictionary<string, string>? Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string? InvocationId
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HubInvocationMessage(string? invocationId)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubMessage.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public abstract class HubMessage
	{
		protected HubMessage()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubMethodInvocationMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public abstract class HubMethodInvocationMessage : HubInvocationMessage
	{
		public string Target
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object?[]? Arguments
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string[]? StreamIds
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		protected HubMethodInvocationMessage(string? invocationId, string target, object?[]? arguments, string[]? streamIds)
		{
			throw null;
		}

		protected HubMethodInvocationMessage(string? invocationId, string target, object?[]? arguments)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\HubProtocolConstants.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public static class HubProtocolConstants
	{
		public const int InvocationMessageType = 1;

		public const int StreamItemMessageType = 2;

		public const int CompletionMessageType = 3;

		public const int StreamInvocationMessageType = 4;

		public const int CancelInvocationMessageType = 5;

		public const int PingMessageType = 6;

		public const int CloseMessageType = 7;
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
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public interface IHubProtocol
	{
		string Name
		{
			get;
		}

		int Version
		{
			get;
		}

		TransferFormat TransferFormat
		{
			get;
		}

		bool TryParseMessage(ref ReadOnlySequence<byte> input, IInvocationBinder binder, [NotNullWhen(true)] out HubMessage message);

		void WriteMessage(HubMessage message, IBufferWriter<byte> output);

		ReadOnlyMemory<byte> GetMessageBytes(HubMessage message);

		bool IsVersionSupported(int version);
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
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\InvocationMessage.cs
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class InvocationMessage : HubMethodInvocationMessage
	{
		public InvocationMessage(string target, object?[]? arguments)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(2)]
		public InvocationMessage(string? invocationId, string target, object?[]? arguments)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(2)]
		public InvocationMessage(string? invocationId, string target, object?[]? arguments, string[]? streamIds)
		{
			throw null;
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
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\StreamBindingFailureMessage.cs
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;

namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class StreamBindingFailureMessage : HubMessage
	{
		public string Id
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public ExceptionDispatchInfo BindingFailure
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public StreamBindingFailureMessage(string id, ExceptionDispatchInfo bindingFailure)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Common\Microsoft.AspNetCore.SignalR.Protocol\StreamInvocationMessage.cs
namespace Microsoft.AspNetCore.SignalR.Protocol
{
	public class StreamInvocationMessage : HubMethodInvocationMessage
	{
		public StreamInvocationMessage(string invocationId, string target, object[] arguments)
		{
			throw null;
		}

		public StreamInvocationMessage(string invocationId, string target, object[] arguments, string[] streamIds)
		{
			throw null;
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
		public object? Item
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public StreamItemMessage(string invocationId, object? item)
		{
			throw null;
		}

		public override string ToString()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.Internal\ISystemClock.cs
using System;

namespace Microsoft.AspNetCore.Internal
{
	internal interface ISystemClock
	{
		DateTimeOffset UtcNow
		{
			get;
		}

		long UtcNowTicks
		{
			get;
		}

		DateTimeOffset UtcNowUnsynchronized
		{
			get;
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
		public static Task SendAsync(this IClientProxy clientProxy, string method, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, object? arg4, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, object? arg4, object? arg5, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, object? arg4, object? arg5, object? arg6, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, object? arg4, object? arg5, object? arg6, object? arg7, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, object? arg4, object? arg5, object? arg6, object? arg7, object? arg8, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, object? arg4, object? arg5, object? arg6, object? arg7, object? arg8, object? arg9, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public static Task SendAsync(this IClientProxy clientProxy, string method, object? arg1, object? arg2, object? arg3, object? arg4, object? arg5, object? arg6, object? arg7, object? arg8, object? arg9, object? arg10, CancellationToken cancellationToken = default(CancellationToken))
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
			throw null;
		}

		public override Task AddToGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task RemoveFromGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendAllAsync(string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendConnectionAsync(string connectionId, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendGroupAsync(string groupName, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendGroupsAsync(IReadOnlyList<string> groupNames, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendGroupExceptAsync(string groupName, string methodName, object?[]? args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendUserAsync(string userId, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken))
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

		public override Task SendAllExceptAsync(string methodName, object?[]? args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendConnectionsAsync(IReadOnlyList<string> connectionIds, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task SendUsersAsync(IReadOnlyList<string> userIds, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken))
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
		public virtual string? GetUserId(HubConnectionContext connection)
		{
			throw null;
		}

		public DefaultUserIdProvider()
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
				throw null;
			}
		}

		protected DynamicHub()
		{
			throw null;
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
			throw null;
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

		public dynamic Groups(IReadOnlyList<string> groupNames)
		{
			throw null;
		}

		public dynamic GroupExcept(string groupName, IReadOnlyList<string> excludedConnectionIds)
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public virtual Task OnConnectedAsync()
		{
			throw null;
		}

		public virtual Task OnDisconnectedAsync(Exception? exception)
		{
			throw null;
		}

		protected virtual void Dispose(bool disposing)
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}

		protected Hub()
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
				throw null;
			}
		}

		protected Hub()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubCallerContext.cs
using Microsoft.AspNetCore.Http.Features;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading;

namespace Microsoft.AspNetCore.SignalR
{
	public abstract class HubCallerContext
	{
		public abstract string ConnectionId
		{
			get;
		}

		public abstract string? UserIdentifier
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get;
		}

		public abstract ClaimsPrincipal? User
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get;
		}

		public abstract IDictionary<object, object?> Items
		{
			get;
		}

		public abstract IFeatureCollection Features
		{
			get;
		}

		public abstract CancellationToken ConnectionAborted
		{
			get;
		}

		public abstract void Abort();

		protected HubCallerContext()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubClientsExtensions.cs
using System.Collections.Generic;

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

		public static T AllExcept<T>(this IHubClients<T> hubClients, IEnumerable<string> excludedConnectionIds)
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

		public static T Clients<T>(this IHubClients<T> hubClients, IEnumerable<string> connectionIds)
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

		public static T Groups<T>(this IHubClients<T> hubClients, IEnumerable<string> groupNames)
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

		public static T GroupExcept<T>(this IHubClients<T> hubClients, string groupName, IEnumerable<string> excludedConnectionIds)
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

		public static T Users<T>(this IHubClients<T> hubClients, IEnumerable<string> userIds)
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
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubConnectionContext
	{
		private static class Log
		{
			public static void HandshakeComplete(ILogger logger, string hubProtocol)
			{
				throw null;
			}

			public static void HandshakeCanceled(ILogger logger)
			{
				throw null;
			}

			public static void SentPing(ILogger logger)
			{
				throw null;
			}

			public static void TransportBufferFull(ILogger logger)
			{
				throw null;
			}

			public static void HandshakeFailed(ILogger logger, Exception exception)
			{
				throw null;
			}

			public static void FailedWritingMessage(ILogger logger, Exception exception)
			{
				throw null;
			}

			public static void ProtocolVersionFailed(ILogger logger, string protocolName, int version)
			{
				throw null;
			}

			public static void AbortFailed(ILogger logger, Exception exception)
			{
				throw null;
			}

			public static void ClientTimeout(ILogger logger, TimeSpan timeout)
			{
				throw null;
			}

			public static void HandshakeSizeLimitExceeded(ILogger logger, long maxMessageSize)
			{
				throw null;
			}
		}

		internal StreamTracker StreamTracker
		{
			get
			{
				throw null;
			}
		}

		internal HubCallerContext HubCallerContext
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		internal Exception? CloseException
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

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

		public virtual ClaimsPrincipal? User
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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

		public virtual IDictionary<object, object?> Items
		{
			get
			{
				throw null;
			}
		}

		internal bool AllowReconnect
		{
			get
			{
				throw null;
			}
		}

		internal PipeReader Input
		{
			get
			{
				throw null;
			}
		}

		public string? UserIdentifier
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			set
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
				throw null;
			}
		}

		internal ConcurrentDictionary<string, CancellationTokenSource> ActiveRequestCancellationSources
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HubConnectionContext(ConnectionContext connectionContext, HubConnectionContextOptions contextOptions, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public virtual ValueTask WriteAsync(HubMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public virtual ValueTask WriteAsync(SerializedHubMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public virtual void Abort()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CHandshakeAsync_003Ed__71))]
		[DebuggerStepThrough]
		internal Task<bool> HandshakeAsync(TimeSpan timeout, IReadOnlyList<string>? supportedProtocols, IHubProtocolResolver protocolResolver, IUserIdProvider userIdProvider, bool enableDetailedErrors)
		{
			throw null;
		}

		internal Task AbortAsync()
		{
			throw null;
		}

		internal void StartClientTimeout()
		{
			throw null;
		}

		internal void BeginClientTimeout()
		{
			throw null;
		}

		internal void StopClientTimeout()
		{
			throw null;
		}

		internal void Cleanup()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubConnectionContextOptions.cs
using Microsoft.AspNetCore.Internal;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubConnectionContextOptions
	{
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
				throw null;
			}
		}

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		internal ISystemClock SystemClock
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public HubConnectionContextOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubConnectionHandler.cs
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubConnectionHandler<THub> : ConnectionHandler where THub : Hub
	{
		private static class Log
		{
			public static void ErrorDispatchingHubEvent(ILogger logger, string hubMethod, Exception exception)
			{
				throw null;
			}

			public static void ErrorProcessingRequest(ILogger logger, Exception exception)
			{
				throw null;
			}

			public static void AbortFailed(ILogger logger, Exception exception)
			{
				throw null;
			}

			public static void ErrorSendingClose(ILogger logger, Exception exception)
			{
				throw null;
			}

			public static void ConnectedStarting(ILogger logger)
			{
				throw null;
			}

			public static void ConnectedEnding(ILogger logger)
			{
				throw null;
			}
		}

		internal ISystemClock SystemClock
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public HubConnectionHandler(HubLifetimeManager<THub> lifetimeManager, IHubProtocolResolver protocolResolver, IOptions<HubOptions> globalHubOptions, IOptions<HubOptions<THub>> hubOptions, ILoggerFactory loggerFactory, IUserIdProvider userIdProvider, IServiceScopeFactory serviceScopeFactory)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(HubConnectionHandler<>._003COnConnectedAsync_003Ed__15))]
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
			private readonly IEnumerator<KeyValuePair<string, HubConnectionContext>> _enumerator;

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
				throw null;
			}

			public bool MoveNext()
			{
				throw null;
			}

			public void Reset()
			{
				throw null;
			}
		}

		public HubConnectionContext? this[string connectionId]
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

		public void Add(HubConnectionContext connection)
		{
			throw null;
		}

		public void Remove(HubConnectionContext connection)
		{
			throw null;
		}

		public Enumerator GetEnumerator()
		{
			throw null;
		}

		public HubConnectionStore()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubInvocationContext.cs
using Microsoft.Extensions.Internal;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubInvocationContext
	{
		internal ObjectMethodExecutor ObjectMethodExecutor
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HubCallerContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Hub Hub
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string HubMethodName
		{
			get
			{
				throw null;
			}
		}

		public IReadOnlyList<object?> HubMethodArguments
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

		public MethodInfo HubMethod
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public HubInvocationContext(HubCallerContext context, IServiceProvider serviceProvider, Hub hub, MethodInfo hubMethod, IReadOnlyList<object?> hubMethodArguments)
		{
			throw null;
		}

		[Obsolete("This constructor is obsolete and will be removed in a future version. The recommended alternative is to use the other constructor.")]
		public HubInvocationContext(HubCallerContext context, string hubMethodName, object?[] hubMethodArguments)
		{
			throw null;
		}

		internal HubInvocationContext(ObjectMethodExecutor objectMethodExecutor, HubCallerContext context, IServiceProvider serviceProvider, Hub hub, object?[] hubMethodArguments)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubLifetimeContext.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.SignalR
{
	public sealed class HubLifetimeContext
	{
		public HubCallerContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Hub Hub
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

		public HubLifetimeContext(HubCallerContext context, IServiceProvider serviceProvider, Hub hub)
		{
			throw null;
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
		public abstract Task OnConnectedAsync(HubConnectionContext connection);

		public abstract Task OnDisconnectedAsync(HubConnectionContext connection);

		public abstract Task SendAllAsync(string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendAllExceptAsync(string methodName, object?[]? args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendConnectionAsync(string connectionId, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendConnectionsAsync(IReadOnlyList<string> connectionIds, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendGroupAsync(string groupName, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendGroupsAsync(IReadOnlyList<string> groupNames, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendGroupExceptAsync(string groupName, string methodName, object?[]? args, IReadOnlyList<string> excludedConnectionIds, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendUserAsync(string userId, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task SendUsersAsync(IReadOnlyList<string> userIds, string methodName, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task AddToGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken));

		public abstract Task RemoveFromGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default(CancellationToken));

		protected HubLifetimeManager()
		{
			throw null;
		}
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
			throw null;
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
			throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public IList<string>? SupportedProtocols
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		internal List<IHubFilter>? HubFilters
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public HubOptions()
		{
			throw null;
		}
	}
	public class HubOptions<THub> : HubOptions where THub : Hub
	{
		internal bool UserHasSetValues
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public HubOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubOptionsExtensions.cs
using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.SignalR
{
	public static class HubOptionsExtensions
	{
		public static void AddFilter(this HubOptions options, IHubFilter hubFilter)
		{
			throw null;
		}

		public static void AddFilter<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TFilter>(this HubOptions options) where TFilter : IHubFilter
		{
			throw null;
		}

		public static void AddFilter(this HubOptions options, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type filterType)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\HubOptionsSetup.cs
using Microsoft.AspNetCore.SignalR.Protocol;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.SignalR
{
	public class HubOptionsSetup : IConfigureOptions<HubOptions>
	{
		internal const int DefaultMaximumMessageSize = 32768;

		internal const int DefaultStreamBufferCapacity = 10;

		internal static TimeSpan DefaultHandshakeTimeout
		{
			get
			{
				throw null;
			}
		}

		internal static TimeSpan DefaultKeepAliveInterval
		{
			get
			{
				throw null;
			}
		}

		internal static TimeSpan DefaultClientTimeoutInterval
		{
			get
			{
				throw null;
			}
		}

		public HubOptionsSetup(IEnumerable<IHubProtocol> protocols)
		{
			throw null;
		}

		public void Configure(HubOptions options)
		{
			throw null;
		}
	}
	public class HubOptionsSetup<THub> : IConfigureOptions<HubOptions<THub>> where THub : Hub
	{
		public HubOptionsSetup(IOptions<HubOptions> options)
		{
			throw null;
		}

		public void Configure(HubOptions<THub> options)
		{
			throw null;
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
		Task SendCoreAsync(string method, object?[]? args, CancellationToken cancellationToken = default(CancellationToken));
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

		T Groups(IReadOnlyList<string> groupNames);

		T GroupExcept(string groupName, IReadOnlyList<string> excludedConnectionIds);

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


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR\IHubFilter.cs
using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR
{
	public interface IHubFilter
	{
		ValueTask<object?> InvokeMethodAsync(HubInvocationContext invocationContext, Func<HubInvocationContext, ValueTask<object?>> next)
		{
			throw null;
		}

		Task OnConnectedAsync(HubLifetimeContext context, Func<HubLifetimeContext, Task> next)
		{
			throw null;
		}

		Task OnDisconnectedAsync(HubLifetimeContext context, Exception? exception, Func<HubLifetimeContext, Exception?, Task> next)
		{
			throw null;
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

		IHubProtocol? GetProtocol(string protocolName, IReadOnlyList<string>? supportedProtocols);
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
		string? GetUserId(HubConnectionContext connection);
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
		public HubMessage? Message
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public SerializedHubMessage(IReadOnlyList<SerializedMessage> messages)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public SerializedHubMessage(HubMessage message)
		{
			throw null;
		}

		public ReadOnlyMemory<byte> GetSerializedMessage(IHubProtocol protocol)
		{
			throw null;
		}

		internal IReadOnlyList<SerializedMessage> GetAllSerializations()
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
		public string ProtocolName
		{
			[System.Runtime.CompilerServices.NullableContext(1)]
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
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.SignalR
{
	public static class SignalRConnectionBuilderExtensions
	{
		public static IConnectionBuilder UseHub<[DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)11)] THub>(this IConnectionBuilder connectionBuilder) where THub : Hub
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.AspNetCore.SignalR.Internal\HubDispatcher.cs
using Microsoft.AspNetCore.SignalR.Protocol;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.SignalR.Internal
{
	internal abstract class HubDispatcher<THub> where THub : Hub
	{
		public abstract Task OnConnectedAsync(HubConnectionContext connection);

		public abstract Task OnDisconnectedAsync(HubConnectionContext connection, Exception? exception);

		public abstract Task DispatchMessageAsync(HubConnectionContext connection, HubMessage hubMessage);

		public abstract IReadOnlyList<Type> GetParameterTypes(string name);

		protected HubDispatcher()
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


// Microsoft.AspNetCore.SignalR.Core\Microsoft.Extensions.Internal\AwaitableInfo.cs
using System;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Internal
{
	internal readonly struct AwaitableInfo
	{
		public Type AwaiterType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public PropertyInfo AwaiterIsCompletedProperty
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MethodInfo AwaiterGetResultMethod
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MethodInfo AwaiterOnCompletedMethod
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MethodInfo AwaiterUnsafeOnCompletedMethod
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Type ResultType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public MethodInfo GetAwaiterMethod
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public AwaitableInfo(Type awaiterType, PropertyInfo awaiterIsCompletedProperty, MethodInfo awaiterGetResultMethod, MethodInfo awaiterOnCompletedMethod, MethodInfo awaiterUnsafeOnCompletedMethod, Type resultType, MethodInfo getAwaiterMethod)
		{
			throw null;
		}

		public static bool IsTypeAwaitable(Type type, out AwaitableInfo awaitableInfo)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.Extensions.Internal\CoercedAwaitableInfo.cs
using System;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Internal
{
	internal readonly struct CoercedAwaitableInfo
	{
		public AwaitableInfo AwaitableInfo
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Expression CoercerExpression
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Type CoercerResultType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool RequiresCoercion
		{
			get
			{
				throw null;
			}
		}

		public CoercedAwaitableInfo(AwaitableInfo awaitableInfo)
		{
			throw null;
		}

		public CoercedAwaitableInfo(Expression coercerExpression, Type coercerResultType, AwaitableInfo coercedAwaitableInfo)
		{
			throw null;
		}

		public static bool IsTypeAwaitable(Type type, out CoercedAwaitableInfo info)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.SignalR.Core\Microsoft.Extensions.Internal\ObjectMethodExecutorAwaitable.cs
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.Extensions.Internal
{
	internal readonly struct ObjectMethodExecutorAwaitable
	{
		public readonly struct Awaiter : ICriticalNotifyCompletion, INotifyCompletion
		{
			private readonly object _customAwaiter;

			private readonly Func<object, bool> _isCompletedMethod;

			private readonly Func<object, object> _getResultMethod;

			private readonly Action<object, Action> _onCompletedMethod;

			private readonly Action<object, Action> _unsafeOnCompletedMethod;

			public bool IsCompleted
			{
				get
				{
					throw null;
				}
			}

			public Awaiter(object customAwaiter, Func<object, bool> isCompletedMethod, Func<object, object> getResultMethod, Action<object, Action> onCompletedMethod, Action<object, Action> unsafeOnCompletedMethod)
			{
				throw null;
			}

			public object GetResult()
			{
				throw null;
			}

			public void OnCompleted(Action continuation)
			{
				throw null;
			}

			public void UnsafeOnCompleted(Action continuation)
			{
				throw null;
			}
		}

		private readonly object _customAwaitable;

		private readonly Func<object, object> _getAwaiterMethod;

		private readonly Func<object, bool> _isCompletedMethod;

		private readonly Func<object, object> _getResultMethod;

		private readonly Action<object, Action> _onCompletedMethod;

		private readonly Action<object, Action> _unsafeOnCompletedMethod;

		public ObjectMethodExecutorAwaitable(object customAwaitable, Func<object, object> getAwaiterMethod, Func<object, bool> isCompletedMethod, Func<object, object> getResultMethod, Action<object, Action> onCompletedMethod, Action<object, Action> unsafeOnCompletedMethod)
		{
			throw null;
		}

		public Awaiter GetAwaiter()
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
				throw null;
			}
		}

		public JsonHubProtocolOptions()
		{
			throw null;
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

		public int Version
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

		public JsonHubProtocol()
		{
			throw null;
		}

		public JsonHubProtocol(IOptions<JsonHubProtocolOptions> options)
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
			throw null;
		}

		public ReadOnlyMemory<byte> GetMessageBytes(HubMessage message)
		{
			throw null;
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


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\DefaultFilesExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class DefaultFilesExtensions
	{
		public static IApplicationBuilder UseDefaultFiles(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseDefaultFiles(this IApplicationBuilder app, string requestPath)
		{
			throw null;
		}

		public static IApplicationBuilder UseDefaultFiles(this IApplicationBuilder app, DefaultFilesOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\DefaultFilesOptions.cs
using Microsoft.AspNetCore.StaticFiles.Infrastructure;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class DefaultFilesOptions : SharedOptionsBase
	{
		public IList<string> DefaultFileNames
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public DefaultFilesOptions()
		{
			throw null;
		}

		public DefaultFilesOptions(SharedOptions sharedOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\DirectoryBrowserExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class DirectoryBrowserExtensions
	{
		public static IApplicationBuilder UseDirectoryBrowser(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseDirectoryBrowser(this IApplicationBuilder app, string requestPath)
		{
			throw null;
		}

		public static IApplicationBuilder UseDirectoryBrowser(this IApplicationBuilder app, DirectoryBrowserOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\DirectoryBrowserOptions.cs
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.StaticFiles.Infrastructure;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class DirectoryBrowserOptions : SharedOptionsBase
	{
		public IDirectoryFormatter Formatter
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public DirectoryBrowserOptions()
		{
			throw null;
		}

		public DirectoryBrowserOptions(SharedOptions sharedOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\FileServerExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class FileServerExtensions
	{
		public static IApplicationBuilder UseFileServer(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseFileServer(this IApplicationBuilder app, bool enableDirectoryBrowsing)
		{
			throw null;
		}

		public static IApplicationBuilder UseFileServer(this IApplicationBuilder app, string requestPath)
		{
			throw null;
		}

		public static IApplicationBuilder UseFileServer(this IApplicationBuilder app, FileServerOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\FileServerOptions.cs
using Microsoft.AspNetCore.StaticFiles.Infrastructure;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class FileServerOptions : SharedOptionsBase
	{
		public StaticFileOptions StaticFileOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DirectoryBrowserOptions DirectoryBrowserOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public DefaultFilesOptions DefaultFilesOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public bool EnableDirectoryBrowsing
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public bool EnableDefaultFiles
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public FileServerOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\StaticFileExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class StaticFileExtensions
	{
		public static IApplicationBuilder UseStaticFiles(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseStaticFiles(this IApplicationBuilder app, string requestPath)
		{
			throw null;
		}

		public static IApplicationBuilder UseStaticFiles(this IApplicationBuilder app, StaticFileOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\StaticFileOptions.cs
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.StaticFiles.Infrastructure;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class StaticFileOptions : SharedOptionsBase
	{
		public IContentTypeProvider ContentTypeProvider
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public string DefaultContentType
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public bool ServeUnknownFileTypes
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public HttpsCompressionMode HttpsCompression
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public Action<StaticFileResponseContext> OnPrepareResponse
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public StaticFileOptions()
		{
			throw null;
		}

		public StaticFileOptions(SharedOptions sharedOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.Builder\StaticFilesEndpointRouteBuilderExtensions.cs
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder
{
	public static class StaticFilesEndpointRouteBuilderExtensions
	{
		public static IEndpointConventionBuilder MapFallbackToFile(this IEndpointRouteBuilder endpoints, string filePath)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapFallbackToFile(this IEndpointRouteBuilder endpoints, string filePath, StaticFileOptions options)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapFallbackToFile(this IEndpointRouteBuilder endpoints, string pattern, string filePath)
		{
			throw null;
		}

		public static IEndpointConventionBuilder MapFallbackToFile(this IEndpointRouteBuilder endpoints, string pattern, string filePath, StaticFileOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\DefaultFilesMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.StaticFiles
{
	public class DefaultFilesMiddleware
	{
		public DefaultFilesMiddleware(RequestDelegate next, IWebHostEnvironment hostingEnv, IOptions<DefaultFilesOptions> options)
		{
			throw null;
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\DirectoryBrowserMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.StaticFiles
{
	public class DirectoryBrowserMiddleware
	{
		public DirectoryBrowserMiddleware(RequestDelegate next, IWebHostEnvironment hostingEnv, IOptions<DirectoryBrowserOptions> options)
		{
			throw null;
		}

		public DirectoryBrowserMiddleware(RequestDelegate next, IWebHostEnvironment hostingEnv, HtmlEncoder encoder, IOptions<DirectoryBrowserOptions> options)
		{
			throw null;
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\FileExtensionContentTypeProvider.cs
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.StaticFiles
{
	public class FileExtensionContentTypeProvider : IContentTypeProvider
	{
		public IDictionary<string, string> Mappings
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FileExtensionContentTypeProvider()
		{
			throw null;
		}

		public FileExtensionContentTypeProvider(IDictionary<string, string> mapping)
		{
			throw null;
		}

		public bool TryGetContentType(string subpath, out string contentType)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\HtmlDirectoryFormatter.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using System.Collections.Generic;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.StaticFiles
{
	public class HtmlDirectoryFormatter : IDirectoryFormatter
	{
		public HtmlDirectoryFormatter(HtmlEncoder encoder)
		{
			throw null;
		}

		public virtual Task GenerateContentAsync(HttpContext context, IEnumerable<IFileInfo> contents)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\IContentTypeProvider.cs
namespace Microsoft.AspNetCore.StaticFiles
{
	public interface IContentTypeProvider
	{
		bool TryGetContentType(string subpath, out string contentType);
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\IDirectoryFormatter.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.StaticFiles
{
	public interface IDirectoryFormatter
	{
		Task GenerateContentAsync(HttpContext context, IEnumerable<IFileInfo> contents);
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\StaticFileContext.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Headers;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.StaticFiles
{
	internal struct StaticFileContext
	{
		internal enum PreconditionState : byte
		{
			Unspecified,
			NotModified,
			ShouldProcess,
			PreconditionFailed
		}

		[Flags]
		private enum RequestType : byte
		{
			Unspecified = 0x0,
			IsHead = 0x1,
			IsGet = 0x2,
			IsRange = 0x4
		}

		private readonly HttpContext _context;

		private readonly StaticFileOptions _options;

		private readonly HttpRequest _request;

		private readonly HttpResponse _response;

		private readonly ILogger _logger;

		private readonly IFileProvider _fileProvider;

		private readonly string _method;

		private readonly string _contentType;

		private IFileInfo _fileInfo;

		private EntityTagHeaderValue _etag;

		private RequestHeaders _requestHeaders;

		private ResponseHeaders _responseHeaders;

		private RangeItemHeaderValue _range;

		private long _length;

		private readonly PathString _subPath;

		private DateTimeOffset _lastModified;

		private PreconditionState _ifMatchState;

		private PreconditionState _ifNoneMatchState;

		private PreconditionState _ifModifiedSinceState;

		private PreconditionState _ifUnmodifiedSinceState;

		private RequestType _requestType;

		public bool IsHeadMethod
		{
			get
			{
				throw null;
			}
		}

		public bool IsGetMethod
		{
			get
			{
				throw null;
			}
		}

		public bool IsRangeRequest
		{
			get
			{
				throw null;
			}
		}

		public string SubPath
		{
			get
			{
				throw null;
			}
		}

		public string PhysicalPath
		{
			get
			{
				throw null;
			}
		}

		public StaticFileContext(HttpContext context, StaticFileOptions options, ILogger logger, IFileProvider fileProvider, string contentType, PathString subPath)
		{
			throw null;
		}

		public bool LookupFileInfo()
		{
			throw null;
		}

		public void ComprehendRequestHeaders()
		{
			throw null;
		}

		public void ApplyResponseHeaders(int statusCode)
		{
			throw null;
		}

		public PreconditionState GetPreconditionState()
		{
			throw null;
		}

		public Task SendStatusAsync(int statusCode)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CServeStaticFile_003Ed__47))]
		[DebuggerStepThrough]
		public Task ServeStaticFile(HttpContext context, RequestDelegate next)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CSendAsync_003Ed__48))]
		[DebuggerStepThrough]
		public Task SendAsync()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CSendRangeAsync_003Ed__49))]
		[DebuggerStepThrough]
		internal Task SendRangeAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\StaticFileMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.StaticFiles
{
	public class StaticFileMiddleware
	{
		public StaticFileMiddleware(RequestDelegate next, IWebHostEnvironment hostingEnv, IOptions<StaticFileOptions> options, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}

		internal static bool ValidatePath(HttpContext context, PathString matchUrl, out PathString subPath)
		{
			throw null;
		}

		internal static bool LookupContentType(IContentTypeProvider contentTypeProvider, StaticFileOptions options, PathString subPath, out string contentType)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles\StaticFileResponseContext.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.StaticFiles
{
	public class StaticFileResponseContext
	{
		public HttpContext Context
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public IFileInfo File
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		[Obsolete("Use the constructor that passes in the HttpContext and IFileInfo parameters: StaticFileResponseContext(HttpContext context, IFileInfo file)", false)]
		public StaticFileResponseContext()
		{
			throw null;
		}

		public StaticFileResponseContext(HttpContext context, IFileInfo file)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles.Infrastructure\SharedOptions.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.StaticFiles.Infrastructure
{
	public class SharedOptions
	{
		public PathString RequestPath
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

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
				throw null;
			}
		}

		public bool RedirectToAppendTrailingSlash
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public SharedOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.AspNetCore.StaticFiles.Infrastructure\SharedOptionsBase.cs
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.StaticFiles.Infrastructure
{
	public abstract class SharedOptionsBase
	{
		protected SharedOptions SharedOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public PathString RequestPath
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public IFileProvider FileProvider
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		public bool RedirectToAppendTrailingSlash
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		protected SharedOptionsBase(SharedOptions sharedOptions)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.StaticFiles\Microsoft.Extensions.DependencyInjection\DirectoryBrowserServiceExtensions.cs
namespace Microsoft.Extensions.DependencyInjection
{
	public static class DirectoryBrowserServiceExtensions
	{
		public static IServiceCollection AddDirectoryBrowser(this IServiceCollection services)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebSockets\Microsoft.AspNetCore.Builder\WebSocketMiddlewareExtensions.cs
namespace Microsoft.AspNetCore.Builder
{
	public static class WebSocketMiddlewareExtensions
	{
		public static IApplicationBuilder UseWebSockets(this IApplicationBuilder app)
		{
			throw null;
		}

		public static IApplicationBuilder UseWebSockets(this IApplicationBuilder app, WebSocketOptions options)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebSockets\Microsoft.AspNetCore.Builder\WebSocketOptions.cs
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.Builder
{
	public class WebSocketOptions
	{
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
				throw null;
			}
		}

		[Obsolete("Setting this property has no effect. It will be removed in a future version.")]
		public int ReceiveBufferSize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public IList<string> AllowedOrigins
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public WebSocketOptions()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebSockets\Microsoft.AspNetCore.WebSockets\ExtendedWebSocketAcceptContext.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.AspNetCore.WebSockets
{
	public class ExtendedWebSocketAcceptContext : WebSocketAcceptContext
	{
		public override string SubProtocol
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		[Obsolete("Setting this property has no effect. It will be removed in a future version.")]
		public int? ReceiveBufferSize
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

		public ExtendedWebSocketAcceptContext()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebSockets\Microsoft.AspNetCore.WebSockets\WebSocketMiddleware.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebSockets
{
	public class WebSocketMiddleware
	{
		private class UpgradeHandshake : IHttpWebSocketFeature
		{
			public bool IsWebSocketRequest
			{
				get
				{
					throw null;
				}
			}

			public UpgradeHandshake(HttpContext context, IHttpUpgradeFeature upgradeFeature, WebSocketOptions options)
			{
				throw null;
			}

			[AsyncStateMachine(typeof(_003CAcceptAsync_003Ed__7))]
			[DebuggerStepThrough]
			public Task<WebSocket> AcceptAsync(WebSocketAcceptContext acceptContext)
			{
				throw null;
			}
		}

		public WebSocketMiddleware(RequestDelegate next, IOptions<WebSocketOptions> options, ILoggerFactory loggerFactory)
		{
			throw null;
		}

		public Task Invoke(HttpContext context)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebSockets\Microsoft.AspNetCore.WebSockets\WebSocketsDependencyInjectionExtensions.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.WebSockets
{
	public static class WebSocketsDependencyInjectionExtensions
	{
		public static IServiceCollection AddWebSockets(this IServiceCollection services, Action<WebSocketOptions> configure)
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
		public static string Encode(byte[] data)
		{
			throw null;
		}

		public static byte[] Decode(string text)
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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class BufferedReadStream : Stream
	{
		public ArraySegment<byte> BufferedData
		{
			[System.Runtime.CompilerServices.NullableContext(0)]
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
				throw null;
			}
		}

		public BufferedReadStream(Stream inner, int bufferSize)
		{
			throw null;
		}

		public BufferedReadStream(Stream inner, int bufferSize, ArrayPool<byte> bytePool)
		{
			throw null;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw null;
		}

		public override void SetLength(long value)
		{
			throw null;
		}

		protected override void Dispose(bool disposing)
		{
			throw null;
		}

		public override void Flush()
		{
			throw null;
		}

		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw null;
		}

		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadAsync_003Ed__33))]
		[DebuggerStepThrough]
		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public bool EnsureBuffered()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CEnsureBufferedAsync_003Ed__35))]
		[DebuggerStepThrough]
		public Task<bool> EnsureBufferedAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public bool EnsureBuffered(int minCount)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CEnsureBufferedAsync_003Ed__37))]
		[DebuggerStepThrough]
		public Task<bool> EnsureBufferedAsync(int minCount, CancellationToken cancellationToken)
		{
			throw null;
		}

		public string ReadLine(int lengthLimit)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadLineAsync_003Ed__39))]
		[DebuggerStepThrough]
		public Task<string> ReadLineAsync(int lengthLimit, CancellationToken cancellationToken)
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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class FileBufferingReadStream : Stream
	{
		public bool InMemory
		{
			get
			{
				throw null;
			}
		}

		public string? TempFileName
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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
				throw null;
			}
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold)
		{
			throw null;
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, Func<string> tempFileDirectoryAccessor)
		{
			throw null;
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, Func<string> tempFileDirectoryAccessor, ArrayPool<byte> bytePool)
		{
			throw null;
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, string tempFileDirectory)
		{
			throw null;
		}

		public FileBufferingReadStream(Stream inner, int memoryThreshold, long? bufferLimit, string tempFileDirectory, ArrayPool<byte> bytePool)
		{
			throw null;
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw null;
		}

		public override int Read(Span<byte> buffer)
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

		[AsyncStateMachine(typeof(_003CReadAsync_003Ed__38))]
		[DebuggerStepThrough]
		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw null;
		}

		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public override void SetLength(long value)
		{
			throw null;
		}

		public override void Flush()
		{
			throw null;
		}

		public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
		{
			throw null;
		}

		protected override void Dispose(bool disposing)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CDisposeAsync_003Ed__45))]
		[DebuggerStepThrough]
		public override ValueTask DisposeAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\FileBufferingWriteStream.cs
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
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

		internal FileStream? FileStream
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
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

		public FileBufferingWriteStream(int memoryThreshold = 32768, long? bufferLimit = null, Func<string>? tempFileDirectoryAccessor = null)
		{
			throw null;
		}

		public override long Seek(long offset, SeekOrigin origin)
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

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CWriteAsync_003Ed__31))]
		[DebuggerStepThrough]
		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			throw null;
		}

		public override void Flush()
		{
			throw null;
		}

		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			throw null;
		}

		public override void SetLength(long value)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CDrainBufferAsync_003Ed__35))]
		[DebuggerStepThrough]
		public Task DrainBufferAsync(Stream destination, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CDrainBufferAsync_003Ed__36))]
		[DebuggerStepThrough]
		public Task DrainBufferAsync(PipeWriter destination, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		protected override void Dispose(bool disposing)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CDisposeAsync_003Ed__38))]
		[DebuggerStepThrough]
		public override ValueTask DisposeAsync()
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
		public MultipartSection Section
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public Stream? FileStream
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
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

		public string FileName
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public FileMultipartSection(MultipartSection section)
		{
			throw null;
		}

		public FileMultipartSection(MultipartSection section, ContentDispositionHeaderValue? header)
		{
			throw null;
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
		public MultipartSection Section
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

		public FormMultipartSection(MultipartSection section)
		{
			throw null;
		}

		public FormMultipartSection(MultipartSection section, ContentDispositionHeaderValue? header)
		{
			throw null;
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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public FormPipeReader(PipeReader pipeReader)
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public FormPipeReader(PipeReader pipeReader, Encoding encoding)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadFormAsync_003Ed__26))]
		[DebuggerStepThrough]
		public Task<Dictionary<string, StringValues>> ReadFormAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		internal void ParseFormValues(ref ReadOnlySequence<byte> buffer, ref KeyValueAccumulator accumulator, bool isFinalBlock)
		{
			throw null;
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
		public const int DefaultValueCountLimit = 1024;

		public const int DefaultKeyLengthLimit = 2048;

		public const int DefaultValueLengthLimit = 4194304;

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
				throw null;
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
				throw null;
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
				throw null;
			}
		}

		public FormReader(string data)
		{
			throw null;
		}

		public FormReader(string data, ArrayPool<char> charPool)
		{
			throw null;
		}

		public FormReader(Stream stream)
		{
			throw null;
		}

		public FormReader(Stream stream, Encoding encoding)
		{
			throw null;
		}

		public FormReader(Stream stream, Encoding encoding, ArrayPool<char> charPool)
		{
			throw null;
		}

		public KeyValuePair<string, string>? ReadNextPair()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadNextPairAsync_003Ed__33))]
		[DebuggerStepThrough]
		public Task<KeyValuePair<string, string>?> ReadNextPairAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public Dictionary<string, StringValues> ReadForm()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadFormAsync_003Ed__43))]
		[DebuggerStepThrough]
		public Task<Dictionary<string, StringValues>> ReadFormAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\HttpRequestStreamReader.cs
using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public class HttpRequestStreamReader : TextReader
	{
		private readonly struct ReadLineStepResult
		{
			public static readonly ReadLineStepResult Done;

			public static readonly ReadLineStepResult Continue;

			public bool Completed
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public string? Result
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public static ReadLineStepResult FromResult(string value)
			{
				throw null;
			}
		}

		public HttpRequestStreamReader(Stream stream, Encoding encoding)
		{
			throw null;
		}

		public HttpRequestStreamReader(Stream stream, Encoding encoding, int bufferSize)
		{
			throw null;
		}

		public HttpRequestStreamReader(Stream stream, Encoding encoding, int bufferSize, ArrayPool<byte> bytePool, ArrayPool<char> charPool)
		{
			throw null;
		}

		protected override void Dispose(bool disposing)
		{
			throw null;
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

		public override int Read(Span<char> buffer)
		{
			throw null;
		}

		public override Task<int> ReadAsync(char[] buffer, int index, int count)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadAsync_003Ed__25))]
		[DebuggerStepThrough]
		public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadLineAsync_003Ed__26))]
		[DebuggerStepThrough]
		public override Task<string?> ReadLineAsync()
		{
			throw null;
		}

		public override string? ReadLine()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadToEndAsync_003Ed__31))]
		[DebuggerStepThrough]
		public override Task<string> ReadToEndAsync()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\HttpResponseStreamWriter.cs
using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
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
			throw null;
		}

		public HttpResponseStreamWriter(Stream stream, Encoding encoding, int bufferSize)
		{
			throw null;
		}

		public HttpResponseStreamWriter(Stream stream, Encoding encoding, int bufferSize, ArrayPool<byte> bytePool, ArrayPool<char> charPool)
		{
			throw null;
		}

		public override void Write(char value)
		{
			throw null;
		}

		public override void Write(char[] values, int index, int count)
		{
			throw null;
		}

		public override void Write(ReadOnlySpan<char> value)
		{
			throw null;
		}

		public override void Write(string? value)
		{
			throw null;
		}

		public override void WriteLine(ReadOnlySpan<char> value)
		{
			throw null;
		}

		public override Task WriteAsync(char value)
		{
			throw null;
		}

		public override Task WriteAsync(char[] values, int index, int count)
		{
			throw null;
		}

		public override Task WriteAsync(string? value)
		{
			throw null;
		}

		public override Task WriteAsync(ReadOnlyMemory<char> value, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override Task WriteLineAsync(ReadOnlyMemory<char> value, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}

		public override void Flush()
		{
			throw null;
		}

		public override Task FlushAsync()
		{
			throw null;
		}

		protected override void Dispose(bool disposing)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CDisposeAsync_003Ed__35))]
		[DebuggerStepThrough]
		public override ValueTask DisposeAsync()
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
		private Dictionary<string, StringValues> _accumulator;

		private Dictionary<string, List<string>> _expandingAccumulator;

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
			readonly get
			{
				throw null;
			}
		}

		public void Append(string key, string value)
		{
			throw null;
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
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public MultipartReader(string boundary, Stream stream)
		{
			throw null;
		}

		public MultipartReader(string boundary, Stream stream, int bufferSize)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CReadNextSectionAsync_003Ed__20))]
		[DebuggerStepThrough]
		public Task<MultipartSection?> ReadNextSectionAsync(CancellationToken cancellationToken = default(CancellationToken))
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
		public string? ContentType
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
		}

		public string? ContentDisposition
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
		}

		public Dictionary<string, StringValues>? Headers
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
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
				throw null;
			}
		}

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
				throw null;
			}
		}

		public MultipartSection()
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\MultipartSectionConverterExtensions.cs
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class MultipartSectionConverterExtensions
	{
		public static FileMultipartSection? AsFileSection(this MultipartSection section)
		{
			throw null;
		}

		public static FormMultipartSection? AsFormDataSection(this MultipartSection section)
		{
			throw null;
		}

		public static ContentDispositionHeaderValue? GetContentDispositionHeader(this MultipartSection section)
		{
			throw null;
		}
	}
}


// Microsoft.AspNetCore.WebUtilities\Microsoft.AspNetCore.WebUtilities\MultipartSectionStreamExtensions.cs
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class MultipartSectionStreamExtensions
	{
		[AsyncStateMachine(typeof(_003CReadAsStringAsync_003Ed__0))]
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
		public static string AddQueryString(string uri, string name, string value)
		{
			throw null;
		}

		public static string AddQueryString(string uri, IDictionary<string, string?> queryString)
		{
			throw null;
		}

		public static string AddQueryString(string uri, IEnumerable<KeyValuePair<string, StringValues>> queryString)
		{
			throw null;
		}

		public static string AddQueryString(string uri, IEnumerable<KeyValuePair<string, string?>> queryString)
		{
			throw null;
		}

		public static Dictionary<string, StringValues> ParseQuery(string queryString)
		{
			throw null;
		}

		public static Dictionary<string, StringValues>? ParseNullableQuery(string queryString)
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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.WebUtilities
{
	public static class StreamHelperExtensions
	{
		public static Task DrainAsync(this Stream stream, CancellationToken cancellationToken)
		{
			throw null;
		}

		public static Task DrainAsync(this Stream stream, long? limit, CancellationToken cancellationToken)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CDrainAsync_003Ed__3))]
		[DebuggerStepThrough]
		public static Task DrainAsync(this Stream stream, ArrayPool<byte> bytePool, long? limit, CancellationToken cancellationToken)
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

		public static byte[] Base64UrlDecode(string input, int offset, int count)
		{
			throw null;
		}

		public static byte[] Base64UrlDecode(string input, int offset, char[] buffer, int bufferOffset, int count)
		{
			throw null;
		}

		public static int GetArraySizeRequiredToDecode(int count)
		{
			throw null;
		}

		public static string Base64UrlEncode(byte[] input)
		{
			throw null;
		}

		public static string Base64UrlEncode(byte[] input, int offset, int count)
		{
			throw null;
		}

		public static int Base64UrlEncode(byte[] input, int offset, char[] output, int outputOffset, int count)
		{
			throw null;
		}

		public static int GetArraySizeRequiredToEncode(int count)
		{
			throw null;
		}

		public static string Base64UrlEncode(ReadOnlySpan<byte> input)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting\Microsoft.Extensions.Hosting\ConsoleLifetimeOptions.cs
namespace Microsoft.Extensions.Hosting
{
	public class ConsoleLifetimeOptions
	{
		public bool SuppressStatusMessages
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

namespace Microsoft.Extensions.Hosting
{
	public class HostBuilder : IHostBuilder
	{
		public IDictionary<object, object> Properties
		{
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

namespace Microsoft.Extensions.Hosting
{
	public class HostOptions
	{
		public TimeSpan ShutdownTimeout
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

namespace Microsoft.Extensions.Hosting.Internal
{
	public class HostingEnvironment : IHostEnvironment, IHostingEnvironment
	{
		public string ApplicationName
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IFileProvider ContentRootFileProvider
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public string ContentRootPath
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public string EnvironmentName
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


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.DependencyInjection\ServiceCollectionHostedServiceExtensions.cs
using Microsoft.Extensions.Hosting;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class ServiceCollectionHostedServiceExtensions
	{
		public static IServiceCollection AddHostedService<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] THostedService>(this IServiceCollection services) where THostedService : class, IHostedService
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

namespace Microsoft.Extensions.Hosting
{
	public class HostBuilderContext
	{
		public IConfiguration Configuration
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IHostEnvironment HostingEnvironment
		{
			get
			{
				throw null;
			}
			set
			{
			}
		}

		public IDictionary<object, object> Properties
		{
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

		public static Task<IHost> StartAsync(this IHostBuilder hostBuilder, CancellationToken cancellationToken = default(CancellationToken))
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Hosting.Abstractions\Microsoft.Extensions.Hosting\HostingAbstractionsHostExtensions.cs
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Extensions.Hosting
{
	public static class HostingAbstractionsHostExtensions
	{
		public static void Run(this IHost host)
		{
		}

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


// Microsoft.Extensions.Hosting.Abstractions\System.Diagnostics.CodeAnalysis\DynamicallyAccessedMemberTypes.cs
namespace System.Diagnostics.CodeAnalysis
{
	[Flags]
	internal enum DynamicallyAccessedMemberTypes
	{
		None = 0x0,
		PublicParameterlessConstructor = 0x1,
		PublicConstructors = 0x3,
		NonPublicConstructors = 0x4,
		PublicMethods = 0x8,
		NonPublicMethods = 0x10,
		PublicFields = 0x20,
		NonPublicFields = 0x40,
		PublicNestedTypes = 0x80,
		NonPublicNestedTypes = 0x100,
		PublicProperties = 0x200,
		NonPublicProperties = 0x400,
		PublicEvents = 0x800,
		NonPublicEvents = 0x1000,
		All = -1
	}
}


// Microsoft.Extensions.Http\Microsoft.Extensions.DependencyInjection\HttpClientBuilderExtensions.cs
using Microsoft.Extensions.Http;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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

		public static IHttpClientBuilder AddTypedClient<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(this IHttpClientBuilder builder) where TClient : class
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

		public static IHttpClientBuilder AddTypedClient<TClient, [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(this IHttpClientBuilder builder) where TClient : class where TImplementation : class, TClient
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

		public static IHttpClientBuilder RedactLoggedHeaders(this IHttpClientBuilder builder, IEnumerable<string> redactedLoggedHeaderNames)
		{
			throw null;
		}

		public static IHttpClientBuilder RedactLoggedHeaders(this IHttpClientBuilder builder, Func<string, bool> shouldRedactHeaderValue)
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
using System.Diagnostics.CodeAnalysis;
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

		public static IHttpClientBuilder AddHttpClient<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(this IServiceCollection services) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(this IServiceCollection services, Action<IServiceProvider, HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(this IServiceCollection services, Action<HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(this IServiceCollection services, string name) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(this IServiceCollection services, string name, Action<IServiceProvider, HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(this IServiceCollection services, string name, Action<HttpClient> configureClient) where TClient : class
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(this IServiceCollection services) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(this IServiceCollection services, Action<IServiceProvider, HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(this IServiceCollection services, Action<HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, Func<HttpClient, IServiceProvider, TImplementation> factory) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, Func<HttpClient, TImplementation> factory) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(this IServiceCollection services, string name) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(this IServiceCollection services, string name, Action<IServiceProvider, HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(this IServiceCollection services, string name, Action<HttpClient> configureClient) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, string name, Func<HttpClient, IServiceProvider, TImplementation> factory) where TClient : class where TImplementation : class, TClient
		{
			throw null;
		}

		public static IHttpClientBuilder AddHttpClient<TClient, TImplementation>(this IServiceCollection services, string name, Func<HttpClient, TImplementation> factory) where TClient : class where TImplementation : class, TClient
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

		public Func<string, bool> ShouldRedactHeaderValue
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
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
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

namespace Microsoft.Extensions.Http
{
	public interface ITypedHttpClientFactory<[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>
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

		public LoggingHttpMessageHandler(ILogger logger, HttpClientFactoryOptions options)
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

		public LoggingScopeHttpMessageHandler(ILogger logger, HttpClientFactoryOptions options)
		{
		}

		[DebuggerStepThrough]
		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			throw null;
		}
	}
}


// Microsoft.Extensions.Http\System.Diagnostics.CodeAnalysis\DynamicallyAccessedMemberTypes.cs
namespace System.Diagnostics.CodeAnalysis
{
	[Flags]
	internal enum DynamicallyAccessedMemberTypes
	{
		None = 0x0,
		PublicParameterlessConstructor = 0x1,
		PublicConstructors = 0x3,
		NonPublicConstructors = 0x4,
		PublicMethods = 0x8,
		NonPublicMethods = 0x10,
		PublicFields = 0x20,
		NonPublicFields = 0x40,
		PublicNestedTypes = 0x80,
		NonPublicNestedTypes = 0x100,
		PublicProperties = 0x200,
		NonPublicProperties = 0x400,
		PublicEvents = 0x800,
		NonPublicEvents = 0x1000,
		All = -1
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

		internal static void AddLocalizationServices(IServiceCollection services)
		{
			throw null;
		}

		internal static void AddLocalizationServices(IServiceCollection services, Action<LocalizationOptions> setupAction)
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
		IList<string>? GetOrAdd(string name, Func<string, IList<string>?> valueFactory);
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\IResourceStringProvider.cs
using System.Collections.Generic;
using System.Globalization;

namespace Microsoft.Extensions.Localization
{
	internal interface IResourceStringProvider
	{
		IList<string>? GetAllResourceStrings(CultureInfo culture, bool throwOnMissing);
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
				throw null;
			}
		}

		public LocalizationOptions()
		{
			throw null;
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
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization\Microsoft.Extensions.Localization\ResourceManagerStringLocalizer.cs
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;

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

		public ResourceManagerStringLocalizer(ResourceManager resourceManager, Assembly resourceAssembly, string baseName, IResourceNamesCache resourceNamesCache, ILogger logger)
		{
			throw null;
		}

		internal ResourceManagerStringLocalizer(ResourceManager resourceManager, AssemblyWrapper resourceAssemblyWrapper, string baseName, IResourceNamesCache resourceNamesCache, ILogger logger)
		{
			throw null;
		}

		internal ResourceManagerStringLocalizer(ResourceManager resourceManager, IResourceStringProvider resourceStringProvider, string baseName, IResourceNamesCache resourceNamesCache, ILogger logger)
		{
			throw null;
		}

		public virtual IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures)
		{
			throw null;
		}

		[IteratorStateMachine(typeof(_003CGetAllStrings_003Ed__14))]
		protected IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures, CultureInfo culture)
		{
			throw null;
		}

		protected string? GetStringSafely(string name, CultureInfo? culture)
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
			throw null;
		}

		protected virtual string GetResourcePrefix(TypeInfo typeInfo)
		{
			throw null;
		}

		protected virtual string GetResourcePrefix(TypeInfo typeInfo, string? baseNamespace, string? resourcesRelativePath)
		{
			throw null;
		}

		protected virtual string GetResourcePrefix(string baseResourceName, string baseNamespace)
		{
			throw null;
		}

		public IStringLocalizer Create(Type resourceSource)
		{
			throw null;
		}

		public IStringLocalizer Create(string baseName, string location)
		{
			throw null;
		}

		protected virtual ResourceManagerStringLocalizer CreateResourceManagerStringLocalizer(Assembly assembly, string baseName)
		{
			throw null;
		}

		protected virtual string GetResourcePrefix(string location, string baseName, string resourceLocation)
		{
			throw null;
		}

		protected virtual ResourceLocationAttribute? GetResourceLocationAttribute(Assembly assembly)
		{
			throw null;
		}

		protected virtual RootNamespaceAttribute? GetRootNamespaceAttribute(Assembly assembly)
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
			throw null;
		}

		public IList<string>? GetOrAdd(string name, Func<string, IList<string>?> valueFactory)
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
			throw null;
		}
	}
}


// Microsoft.Extensions.Localization.Abstractions\Microsoft.Extensions.Localization\IStringLocalizer.cs
using System.Collections.Generic;

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
		IStringLocalizer Create(Type resourceSource);

		IStringLocalizer Create(string baseName, string location);
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

		public string Value
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

		public string? SearchedLocation
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public LocalizedString(string name, string value)
		{
			throw null;
		}

		public LocalizedString(string name, string value, bool resourceNotFound)
		{
			throw null;
		}

		public LocalizedString(string name, string value, bool resourceNotFound, string? searchedLocation)
		{
			throw null;
		}

		public static implicit operator string?(LocalizedString localizedString)
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
using System.Collections.Generic;

namespace Microsoft.Extensions.Localization
{
	public class StringLocalizer<TResourceSource> : IStringLocalizer<TResourceSource>, IStringLocalizer
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
			throw null;
		}

		public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures)
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
		public static LocalizedString GetString(this IStringLocalizer stringLocalizer, string name)
		{
			throw null;
		}

		public static LocalizedString GetString(this IStringLocalizer stringLocalizer, string name, params object[] arguments)
		{
			throw null;
		}

		public static IEnumerable<LocalizedString> GetAllStrings(this IStringLocalizer stringLocalizer)
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
		public TextEncoderSettings? TextEncoderSettings
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
			[CompilerGenerated]
			set
			{
				throw null;
			}
		}

		public WebEncoderOptions()
		{
			throw null;
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

		public override string Encode(string value)
		{
			throw null;
		}

		public override void Encode(TextWriter output, char[] value, int startIndex, int characterCount)
		{
			throw null;
		}

		public override void Encode(TextWriter output, string value, int startIndex, int characterCount)
		{
			throw null;
		}

		public override bool WillEncode(int unicodeScalar)
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

		public HtmlTestEncoder()
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

		public override string Encode(string value)
		{
			throw null;
		}

		public override void Encode(TextWriter output, char[] value, int startIndex, int characterCount)
		{
			throw null;
		}

		public override void Encode(TextWriter output, string value, int startIndex, int characterCount)
		{
			throw null;
		}

		public override bool WillEncode(int unicodeScalar)
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

		public JavaScriptTestEncoder()
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

		public override string Encode(string value)
		{
			throw null;
		}

		public override void Encode(TextWriter output, char[] value, int startIndex, int characterCount)
		{
			throw null;
		}

		public override void Encode(TextWriter output, string value, int startIndex, int characterCount)
		{
			throw null;
		}

		public override bool WillEncode(int unicodeScalar)
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

		public UrlTestEncoder()
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\DotNetObjectReference.cs
using Microsoft.JSInterop.Infrastructure;
using System;
using System.Runtime.CompilerServices;

namespace Microsoft.JSInterop
{
	public static class DotNetObjectReference
	{
		public static DotNetObjectReference<TValue> Create<TValue>(TValue value) where TValue : class
		{
			throw null;
		}
	}
	public sealed class DotNetObjectReference<TValue> : IDotNetObjectReference, IDisposable where TValue : class
	{
		public TValue Value
		{
			get
			{
				throw null;
			}
		}

		internal long ObjectId
		{
			get
			{
				throw null;
			}
			set
			{
				throw null;
			}
		}

		internal JSRuntime? JSRuntime
		{
			[System.Runtime.CompilerServices.NullableContext(2)]
			get
			{
				throw null;
			}
			[System.Runtime.CompilerServices.NullableContext(2)]
			set
			{
				throw null;
			}
		}

		object IDotNetObjectReference.Value
		{
			get
			{
				throw null;
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

		internal DotNetObjectReference(TValue value)
		{
			throw null;
		}

		public void Dispose()
		{
			throw null;
		}

		internal void ThrowIfDisposed()
		{
			throw null;
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
			throw null;
		}

		public JSException(string message, Exception innerException)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSInProcessRuntime.cs
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.JSInterop
{
	public abstract class JSInProcessRuntime : JSRuntime, IJSInProcessRuntime, IJSRuntime
	{
		[return: MaybeNull]
		public TValue Invoke<TValue>(string identifier, params object[] args)
		{
			throw null;
		}

		protected abstract string? InvokeJS(string identifier, string? argsJson);

		protected JSInProcessRuntime()
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
			throw null;
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
		public string? Identifier
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public JSInvokableAttribute()
		{
			throw null;
		}

		[System.Runtime.CompilerServices.NullableContext(1)]
		public JSInvokableAttribute(string identifier)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSRuntime.cs
using Microsoft.JSInterop.Infrastructure;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.JSInterop
{
	public abstract class JSRuntime : IJSRuntime
	{
		protected internal JsonSerializerOptions JsonSerializerOptions
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

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
				throw null;
			}
		}

		protected JSRuntime()
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvokeAsync_003Ed__13<>))]
		[DebuggerStepThrough]
		public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object[] args)
		{
			throw null;
		}

		public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object[] args)
		{
			throw null;
		}

		protected abstract void BeginInvokeJS(long taskId, string identifier, string? argsJson);

		protected internal abstract void EndInvokeDotNet(DotNetInvocationInfo invocationInfo, in DotNetInvocationResult invocationResult);

		internal void EndInvokeJS(long taskId, bool succeeded, ref Utf8JsonReader jsonReader)
		{
			throw null;
		}

		internal long TrackObjectReference<TValue>(DotNetObjectReference<TValue> dotNetObjectReference) where TValue : class
		{
			throw null;
		}

		internal IDotNetObjectReference GetObjectReference(long dotNetObjectId)
		{
			throw null;
		}

		internal void ReleaseObjectReference(long dotNetObjectId)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop\JSRuntimeExtensions.cs
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.JSInterop
{
	public static class JSRuntimeExtensions
	{
		[AsyncStateMachine(typeof(_003CInvokeVoidAsync_003Ed__0))]
		[DebuggerStepThrough]
		public static ValueTask InvokeVoidAsync(this IJSRuntime jsRuntime, string identifier, params object[] args)
		{
			throw null;
		}

		public static ValueTask<TValue> InvokeAsync<TValue>(this IJSRuntime jsRuntime, string identifier, params object[] args)
		{
			throw null;
		}

		public static ValueTask<TValue> InvokeAsync<TValue>(this IJSRuntime jsRuntime, string identifier, CancellationToken cancellationToken, params object[] args)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvokeVoidAsync_003Ed__3))]
		[DebuggerStepThrough]
		public static ValueTask InvokeVoidAsync(this IJSRuntime jsRuntime, string identifier, CancellationToken cancellationToken, params object[] args)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvokeAsync_003Ed__4<>))]
		[DebuggerStepThrough]
		public static ValueTask<TValue> InvokeAsync<TValue>(this IJSRuntime jsRuntime, string identifier, TimeSpan timeout, params object[] args)
		{
			throw null;
		}

		[AsyncStateMachine(typeof(_003CInvokeVoidAsync_003Ed__5))]
		[DebuggerStepThrough]
		public static ValueTask InvokeVoidAsync(this IJSRuntime jsRuntime, string identifier, TimeSpan timeout, params object[] args)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop.Infrastructure\DotNetDispatcher.cs
using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Microsoft.JSInterop.Infrastructure
{
	public static class DotNetDispatcher
	{
		private readonly struct AssemblyKey : IEquatable<AssemblyKey>
		{
			public Assembly? Assembly
			{
				[System.Runtime.CompilerServices.NullableContext(2)]
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public string AssemblyName
			{
				[CompilerGenerated]
				get
				{
					throw null;
				}
			}

			public AssemblyKey(Assembly assembly)
			{
				throw null;
			}

			public AssemblyKey(string assemblyName)
			{
				throw null;
			}

			public bool Equals(AssemblyKey other)
			{
				throw null;
			}

			public override int GetHashCode()
			{
				throw null;
			}
		}

		internal static readonly JsonEncodedText DotNetObjectRefKey;

		public static string? Invoke(JSRuntime jsRuntime, in DotNetInvocationInfo invocationInfo, string argsJson)
		{
			throw null;
		}

		public static void BeginInvokeDotNet(JSRuntime jsRuntime, DotNetInvocationInfo invocationInfo, string argsJson)
		{
			throw null;
		}

		internal static object?[] ParseArguments(JSRuntime jsRuntime, string methodIdentifier, string arguments, Type[] parameterTypes)
		{
			throw null;
		}

		public static void EndInvokeJS(JSRuntime jsRuntime, string arguments)
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
		public string AssemblyName
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

		public long DotNetObjectId
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
		public Exception? Exception
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public string? ErrorKind
		{
			[CompilerGenerated]
			get
			{
				throw null;
			}
		}

		public object? Result
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

		[System.Runtime.CompilerServices.NullableContext(1)]
		public DotNetInvocationResult(Exception exception, string? errorKind)
		{
			throw null;
		}

		public DotNetInvocationResult(object? result)
		{
			throw null;
		}
	}
}


// Microsoft.JSInterop\Microsoft.JSInterop.Infrastructure\IDotNetObjectReference.cs
using System;

namespace Microsoft.JSInterop.Infrastructure
{
	internal interface IDotNetObjectReference : IDisposable
	{
		object Value
		{
			get;
		}
	}
}


