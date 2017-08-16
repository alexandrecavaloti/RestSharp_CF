﻿#region License
//   Copyright 2010 John Sheehan
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//	 http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License. 
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
#if NET4 || MONODROID || MONOTOUCH
using System.Threading.Tasks;
#endif
using System.Text;
using System.Net;

using RestSharp.Extensions;

namespace RestSharp
{
	public partial class RestClient
	{
		/// <summary>
		/// Executes the request and callback asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		/// <param name="callback">Callback function to be executed upon completion providing access to the async handle.</param>
		public virtual RestRequestAsyncHandle ExecuteAsync(IRestRequest request, Action<IRestResponse, RestRequestAsyncHandle> callback)
		{

				string method = request.Method.ToString();
				switch (request.Method)
				{
						case Method.PATCH:
						case Method.POST:
						case Method.PUT:
							return ExecuteAsync(request, callback, method, DoAsPostAsync);
						default:
							return ExecuteAsync(request, callback, method, DoAsGetAsync);
				}
		}

		/// <summary>
		/// Executes a GET-style request and callback asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		/// <param name="callback">Callback function to be executed upon completion providing access to the async handle.</param>
		/// <param name="httpMethod">The HTTP method to execute</param>
		public virtual RestRequestAsyncHandle ExecuteAsyncGet(IRestRequest request, Action<IRestResponse, RestRequestAsyncHandle> callback, string httpMethod)
		{
			return ExecuteAsync(request, callback, httpMethod, DoAsGetAsync);
		}

		/// <summary>
		/// Executes a POST-style request and callback asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		/// <param name="callback">Callback function to be executed upon completion providing access to the async handle.</param>
		/// <param name="httpMethod">The HTTP method to execute</param>
		public virtual RestRequestAsyncHandle ExecuteAsyncPost(IRestRequest request, Action<IRestResponse, RestRequestAsyncHandle> callback, string httpMethod)
		{
			request.Method = Method.POST;  // Required by RestClient.BuildUri... 
			return ExecuteAsync(request, callback, httpMethod, DoAsPostAsync);
		}

        private RestRequestAsyncHandle ExecuteAsync(IRestRequest request, Action<IRestResponse, RestRequestAsyncHandle> callback, string httpMethod, Func<IHttp, Action<HttpResponse>, string, HttpWebRequest> getWebRequest)
        {
            var http = HttpFactory.Create();
            AuthenticateIfNeeded(this, request);

            ConfigureHttp(request, http);

            var asyncHandle = new RestRequestAsyncHandle();

            Action<HttpResponse> response_cb = r => ProcessResponse(request, r, asyncHandle, callback);

            //if (UseSynchronizationContext && SynchronizationContext.Current != null)
            //if (UseSynchronizationContext)
            //{
            //    //var ctx = SynchronizationContext.Current;
            //    var cb = response_cb;

            //    response_cb = resp => ctx.Post(s => cb(resp), null);
            //}

            asyncHandle.WebRequest = getWebRequest(http, response_cb, httpMethod);
            return asyncHandle;
        }

		private static HttpWebRequest DoAsGetAsync(IHttp http, Action<HttpResponse> response_cb, string method)
		{
			return http.AsGetAsync(response_cb, method);
		}

		private static HttpWebRequest DoAsPostAsync(IHttp http, Action<HttpResponse> response_cb, string method)
		{
			return http.AsPostAsync(response_cb, method);
		}

		private void ProcessResponse(IRestRequest request, HttpResponse httpResponse, RestRequestAsyncHandle asyncHandle, Action<IRestResponse, RestRequestAsyncHandle> callback)
		{
			var restResponse = ConvertToRestResponse(request, httpResponse);
			callback(restResponse, asyncHandle);
		}

        

		/// <summary>
		/// Executes the request and callback asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		/// <param name="callback">Callback function to be executed upon completion</param>
		public virtual RestRequestAsyncHandle ExecuteAsync<T>(IRestRequest request, Action<IRestResponse<T>, RestRequestAsyncHandle> callback)
		{
			return ExecuteAsync(request, (response, asyncHandle) => DeserializeResponse(request, callback, response, asyncHandle));
		}

		/// <summary>
		/// Executes a GET-style request and callback asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		/// <param name="callback">Callback function to be executed upon completion</param>
		/// <param name="httpMethod">The HTTP method to execute</param>
		public virtual RestRequestAsyncHandle ExecuteAsyncGet<T>(IRestRequest request, Action<IRestResponse<T>, RestRequestAsyncHandle> callback, string httpMethod)
		{
			return ExecuteAsyncGet(request, (response, asyncHandle) => DeserializeResponse(request, callback, response, asyncHandle), httpMethod);
		}

		/// <summary>
		/// Executes a POST-style request and callback asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		/// <param name="callback">Callback function to be executed upon completion</param>
		/// <param name="httpMethod">The HTTP method to execute</param>
		public virtual RestRequestAsyncHandle ExecuteAsyncPost<T>(IRestRequest request, Action<IRestResponse<T>, RestRequestAsyncHandle> callback, string httpMethod)
		{
			return ExecuteAsyncPost(request, (response, asyncHandle) => DeserializeResponse(request, callback, response, asyncHandle), httpMethod);
		}

		private void DeserializeResponse<T>(IRestRequest request, Action<IRestResponse<T>, RestRequestAsyncHandle> callback, IRestResponse response, RestRequestAsyncHandle asyncHandle)
		{
			IRestResponse<T> restResponse = response as RestResponse<T>;
			if (response.ResponseStatus == ResponseStatus.Completed)
			{
				restResponse = Deserialize<T>(request, response);
			}

			callback(restResponse, asyncHandle);
		}

        /// <summary>
        /// Executes the request and returns a response, authenticating if needed
        /// </summary>
        /// <param name="request">Request to be executed</param>
        /// <returns>RestResponse</returns>
        public virtual IRestResponse Execute(IRestRequest request)
        {
            //string method = Enum.GetName(typeof(Method), request.Method);
            string method = request.Method.ToString();

            switch (request.Method)
            {
                case Method.POST:
                case Method.PUT:
                case Method.PATCH:                
                    return this.Execute(request, method, DoExecuteAsPost);

                default:
                    return this.Execute(request, method, DoExecuteAsGet);
            }
        }

        private IRestResponse Execute(IRestRequest request, string httpMethod,
           Func<IHttp, string, HttpResponse> getResponse)
        {
            this.AuthenticateIfNeeded(this, request);

            IRestResponse response = new RestResponse();

            try
            {
                IHttp http = this.HttpFactory.Create();

                this.ConfigureHttp(request, http);

                response = ConvertToRestResponse(request, getResponse(http, httpMethod));
                response.Request = request;
                response.Request.IncreaseNumAttempts();
            }
            catch (Exception ex)
            {
                response.ResponseStatus = ResponseStatus.Error;
                response.ErrorMessage = ex.Message;
                response.ErrorException = ex;
            }

            return response;
        }

        /// <summary>
        /// Executes the specified request and deserializes the response content using the appropriate content handler
        /// </summary>
        /// <typeparam name="T">Target deserialization type</typeparam>
        /// <param name="request">Request to execute</param>
        /// <returns>RestResponse[[T]] with deserialized data in Data property</returns>
        public virtual IRestResponse<T> Execute<T>(IRestRequest request) where T : new()
        {
            return this.Deserialize<T>(request, this.Execute(request));
        }

        //public IRestResponse<T> ExecuteAsGet<T>(IRestRequest request, string httpMethod) where T : new()
        //{
        //    return this.Deserialize<T>(request, this.ExecuteAsGet(request, httpMethod));
        //}

        //public IRestResponse<T> ExecuteAsPost<T>(IRestRequest request, string httpMethod) where T : new()
        //{
        //    return this.Deserialize<T>(request, this.ExecuteAsPost(request, httpMethod));
        //}

        private static HttpResponse DoExecuteAsGet(IHttp http, string method)
        {
            return http.AsGet(method);
        }

        private static HttpResponse DoExecuteAsPost(IHttp http, string method)
        {
            return http.AsPost(method);
        }


#if NET4 || MONODROID || MONOTOUCH
		/// <summary>
		/// Executes a GET-style request asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		public virtual Task<IRestResponse<T>> ExecuteGetTaskAsync<T>(IRestRequest request)
		{
			return ExecuteGetTaskAsync<T>(request, CancellationToken.None);
		}

		/// <summary>
		/// Executes a GET-style request asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		/// <param name="token">The cancellation token</param>
		public virtual Task<IRestResponse<T>> ExecuteGetTaskAsync<T>(IRestRequest request, CancellationToken token)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}

			request.Method = Method.GET;
			return ExecuteTaskAsync<T>(request, token);
		}

		/// <summary>
		/// Executes a POST-style request asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		public virtual Task<IRestResponse<T>> ExecutePostTaskAsync<T>(IRestRequest request)
		{
			return ExecutePostTaskAsync<T>(request, CancellationToken.None);
		}

		/// <summary>
		/// Executes a POST-style request asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		/// <param name="token">The cancellation token</param>
		public virtual Task<IRestResponse<T>> ExecutePostTaskAsync<T>(IRestRequest request, CancellationToken token)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}

			request.Method = Method.POST;
			return ExecuteTaskAsync<T>(request, token);
		}

		/// <summary>
		/// Executes the request asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		public virtual Task<IRestResponse<T>> ExecuteTaskAsync<T>(IRestRequest request)
		{
			return ExecuteTaskAsync<T>(request, CancellationToken.None);
		}

		/// <summary>
		/// Executes the request asynchronously, authenticating if needed
		/// </summary>
		/// <typeparam name="T">Target deserialization type</typeparam>
		/// <param name="request">Request to be executed</param>
		/// <param name="token">The cancellation token</param>
		public virtual Task<IRestResponse<T>> ExecuteTaskAsync<T>(IRestRequest request, CancellationToken token)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}

			var taskCompletionSource = new TaskCompletionSource<IRestResponse<T>>();

			try
			{
				var async = ExecuteAsync<T>(request, (response, _) =>
					{
						if (token.IsCancellationRequested)
						{
							taskCompletionSource.TrySetCanceled();
						}
						else if (response.ErrorException != null)
						{
							taskCompletionSource.TrySetException(response.ErrorException);
						}
						else if (response.ResponseStatus != ResponseStatus.Completed)
						{
							taskCompletionSource.TrySetException(response.ResponseStatus.ToWebException());
						}
						else
						{
							taskCompletionSource.TrySetResult(response);
						}
					});

				token.Register(() =>
					{
						async.Abort();
						taskCompletionSource.TrySetCanceled();
					});
			}
			catch (Exception ex)
			{
				taskCompletionSource.TrySetException(ex);
			}

			return taskCompletionSource.Task;
		}

		/// <summary>
		/// Executes the request asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		public virtual Task<IRestResponse> ExecuteTaskAsync(IRestRequest request)
		{
			return ExecuteTaskAsync(request, CancellationToken.None);
		}

		/// <summary>
		/// Executes a GET-style asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		public virtual Task<IRestResponse> ExecuteGetTaskAsync(IRestRequest request)
		{
			return this.ExecuteGetTaskAsync(request, CancellationToken.None);
		}

		/// <summary>
		/// Executes a GET-style asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		/// <param name="token">The cancellation token</param>
		public virtual Task<IRestResponse> ExecuteGetTaskAsync(IRestRequest request, CancellationToken token)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}

			request.Method = Method.GET;
			return ExecuteTaskAsync(request, token);
		}

		/// <summary>
		/// Executes a POST-style asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		public virtual Task<IRestResponse> ExecutePostTaskAsync(IRestRequest request)
		{
			return this.ExecutePostTaskAsync(request, CancellationToken.None);
		}

		/// <summary>
		/// Executes a POST-style asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		/// <param name="token">The cancellation token</param>
		public virtual Task<IRestResponse> ExecutePostTaskAsync(IRestRequest request, CancellationToken token)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}

			request.Method = Method.POST;
			return ExecuteTaskAsync(request, token);
		}

		/// <summary>
		/// Executes the request asynchronously, authenticating if needed
		/// </summary>
		/// <param name="request">Request to be executed</param>
		/// <param name="token">The cancellation token</param>
		public virtual Task<IRestResponse> ExecuteTaskAsync(IRestRequest request, CancellationToken token)
		{
			if (request == null)
			{
				throw new ArgumentNullException("request");
			}

			var taskCompletionSource = new TaskCompletionSource<IRestResponse>();

			try
			{
				var async = this.ExecuteAsync(request, (response, _) =>
					{
						if (token.IsCancellationRequested)
						{
							taskCompletionSource.TrySetCanceled();
						}
						else if (response.ErrorException != null)
						{
							taskCompletionSource.TrySetException(response.ErrorException);
						}
						else if (response.ResponseStatus != ResponseStatus.Completed)
						{
							taskCompletionSource.TrySetException(response.ResponseStatus.ToWebException());
						}
						else
						{
							taskCompletionSource.TrySetResult(response);
						}
					});

				token.Register(() =>
					{
						async.Abort();
						taskCompletionSource.TrySetCanceled();
					});
			}
			catch (Exception ex)
			{
				taskCompletionSource.TrySetException(ex);
			}

			return taskCompletionSource.Task;
		}
#endif
	}
}