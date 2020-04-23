
Configuring request options in Browser WebAssembly

Before we look at our requirement in .NET, let's look at `fetch`. .NET WebAssembly implementation for HttpClient uses Browser's "fetch API" as it's transport. 

In it's simplest format, all you need to perform a HTTP request using `fetch` is to specify a url:

```js
const response = await fetch('products/get'); // Perform a GET request to products/get
const products = await response.json();       // Read the response body as json
```

Additional options to configure the request are passed in a secondary options type:

```js
const response = await fetch('products/post', {
    method: 'POST',
    body: valueToSend,
    headers: {
        'Content-Type': 'application/json'
    }
});
```

fetch does not have a way to options that apply globally or to more than one request, all options must be configured per-request. Application developers may use helper methods for options that need to be configured frequently (for eg https://github.com/moll/js-fetch-defaults#using).

In the code sample above, `HttpRequestMessage` has properties to configure the 3 values that were passed in as `fetch` options. However, in addition to the `method`, `body` and `headers` parameters, `fetch` has a few other options that need to be configured on a per-request basis. See https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/fetch#Syntax `HttpRequestMessage` does not have a very nice way to specify or configure these. 

We will go over some of the more commonly used options:

1) Cache (https://developer.mozilla.org/en-US/docs/Web/API/Request/cache)

Browsers cache results and will return results from the caches. `fetch` has ways to force the browser to ignore locally cached resources and perform requests. Cache-busting is an important tool in a web developer arsenal.

```js
// In this sample, we ensure the catalog is always updated from the server.
const response = await fetch('products/catalog.json', { cache: 'no-cache' });
```

If an equivalent option is offered to .NET WebAssembly developers, it is essential that it is available as a per-request setting. Changing cache settings globally is not desirable.


2) Integrity (https://developer.mozilla.org/en-US/docs/Web/API/Request/integrity)

[Subresource integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) is a browser security feature that allows a response to only be read if the contents match the specified hash. It ensures that content downloaded to the browser haven't been tampered with in anyway. This is typically valuable if an application downloaded content from a 3rd party hosted site. For e.g.

```js
// The application defers downloading a large payload until it's necessary. It uses integrity to ensure the contents are as expected.
if (shouldShowGrid()) {
    const data = await fetch('https://raw.githubusercontent.com/mydata/large.data.json', { integrity: 'precomuted-sha-goes-here' }).then(r => r.json());
    showGrid(data);
}
```

Like the cache option, `integrity` must be a per-request option.

3) Credentials (https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials)

When performing a fetch request, browsers will default to not including the cookie header as part of the request. If your site relies on cookies for authentication, you need these to included. The `credentials` option allows configuring these:


```js
const response = await fetch('products/get', { credentials: 'include' });
```

Specifying `credentials` option is mutually exclusive to specifying a value for the `Authorization` header. While there might be merits to specifying credentials on a per-request basis, .NET users have been accustomed to configuring it on `HttpClientHandler`. We could conceive of a `Credentials` options type with well-known instances that WASM's HttpClient would use to configure this property.

4) Streamed versus buffered responses

The response returned from a fetch operation has methods to read it as bytes, strings, json etc. In addition, browsers allow reading the body as a raw (unbuffered) stream. Some applications such as gRPC Web's server streaming feature require streaming responses. 
.NET WebAssembly has an implementation of StreamContent over the response body. When they attempted to make it the default, they received user feedback stating that performing sync reads on this content would result in application deadlocks (WASM is single-threaded). There was enough feedback where they feel the need to make returning an unbuffered stream content an option that users have to opt-into.

