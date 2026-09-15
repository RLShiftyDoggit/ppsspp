// Copyright (c) 2012- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#pragma once

#include <map>
#include "Common/Log.h"
#include "Common/Net/HTTPClient.h"
#include "Common/Net/LegacyFTB3HTTPClient.h"

#define 	SCE_HTTP_DEFAULT_RESOLVER_TIMEOUT   (1 * 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_RESOLVER_RETRY   (5U)
#define 	SCE_HTTP_DEFAULT_CONNECT_TIMEOUT   (30* 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_SEND_TIMEOUT   (120* 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_RECV_TIMEOUT   (120* 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_RECV_BLOCK_SIZE   (1500U)
#define 	SCE_HTTP_DEFAULT_RESPONSE_HEADER_MAX   (5000U)
#define 	SCE_HTTP_DEFAULT_REDIRECT_MAX   (6U)
#define 	SCE_HTTP_DEFAULT_TRY_AUTH_MAX   (6U)
#define 	SCE_HTTP_INVALID_ID   0
#define 	SCE_HTTP_ENABLE   (1)
#define 	SCE_HTTP_DISABLE   (0)
#define 	SCE_HTTP_USERNAME_MAX_SIZE   256
#define 	SCE_HTTP_PASSWORD_MAX_SIZE   256

enum SceHttpErrorCode {
	SCE_HTTP_ERROR_BEFORE_INIT = 0x80431001,
	SCE_HTTP_ERROR_NOT_SUPPORTED = 0x80431004,
	SCE_HTTP_ERROR_ALREADY_INITED = 0x80431020,
	SCE_HTTP_ERROR_BUSY = 0x80431021,
	SCE_HTTP_ERROR_OUT_OF_MEMORY = 0x80431022,
	SCE_HTTP_ERROR_NOT_FOUND = 0x80431025,
	SCE_HTTP_ERROR_UNKNOWN_SCHEME = 0x80431061,
	SCE_HTTP_ERROR_NETWORK = 0x80431063,
	SCE_HTTP_ERROR_BAD_RESPONSE = 0x80431064,
	SCE_HTTP_ERROR_BEFORE_SEND = 0x80431065,
	SCE_HTTP_ERROR_AFTER_SEND = 0x80431066,
	SCE_HTTP_ERROR_TIMEOUT = 0x80431068,
	SCE_HTTP_ERROR_UNKOWN_AUTH_TYPE = 0x80431069,
	SCE_HTTP_ERROR_INVALID_VERSION = 0x8043106A,
	SCE_HTTP_ERROR_UNKNOWN_METHOD = 0x8043106B,
	SCE_HTTP_ERROR_READ_BY_HEAD_METHOD = 0x8043106F,
	SCE_HTTP_ERROR_NOT_IN_COM = 0x80431070,
	SCE_HTTP_ERROR_NO_CONTENT_LENGTH = 0x80431071,
	SCE_HTTP_ERROR_CHUNK_ENC = 0x80431072,
	SCE_HTTP_ERROR_TOO_LARGE_RESPONSE_HEADER = 0x80431073,
	SCE_HTTP_ERROR_SSL = 0x80431075,
	SCE_HTTP_ERROR_INSUFFICIENT_HEAPSIZE = 0x80431077,
	SCE_HTTP_ERROR_BEFORE_COOKIE_LOAD = 0x80431078,
	SCE_HTTP_ERROR_ABORTED = 0x80431080,
	SCE_HTTP_ERROR_UNKNOWN = 0x80431081,
	SCE_HTTP_ERROR_INVALID_ID = 0x80431100,
	SCE_HTTP_ERROR_OUT_OF_SIZE = 0x80431104,
	SCE_HTTP_ERROR_INVALID_VALUE = 0x804311FE,
	SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND = 0x80432025,
	SCE_HTTP_ERROR_PARSE_HTTP_INVALID_RESPONSE = 0x80432060,
	SCE_HTTP_ERROR_PARSE_HTTP_INVALID_VALUE = 0x804321FE,
	SCE_HTTP_ERROR_INVALID_URL = 0x80433060,
	SCE_HTTP_ERROR_RESOLVER_EPACKET = 0x80436001,
	SCE_HTTP_ERROR_RESOLVER_ENODNS = 0x80436002,
	SCE_HTTP_ERROR_RESOLVER_ETIMEDOUT = 0x80436003,
	SCE_HTTP_ERROR_RESOLVER_ENOSUPPORT = 0x80436004,
	SCE_HTTP_ERROR_RESOLVER_EFORMAT = 0x80436005,
	SCE_HTTP_ERROR_RESOLVER_ESERVERFAILURE = 0x80436006,
	SCE_HTTP_ERROR_RESOLVER_ENOHOST = 0x80436007,
	SCE_HTTP_ERROR_RESOLVER_ENOTIMPLEMENTED = 0x80436008,
	SCE_HTTP_ERROR_RESOLVER_ESERVERREFUSED = 0x80436009,
	SCE_HTTP_ERROR_RESOLVER_ENORECORD = 0x8043600A
};

enum SceHttpsErrorCode {
	SCE_SSL_ERROR_NOT_INIT = 0x80435001,
	SCE_SSL_ERROR_ALREADY_INIT = 0x80435020,
	SCE_HTTPS_ERROR_OUT_OF_MEMORY = 0x80435022,
	SCE_HTTPS_ERROR_CERT = 0x80435060,
	SCE_HTTPS_ERROR_HANDSHAKE = 0x80435061,
	SCE_HTTPS_ERROR_IO = 0x80435062,
	SCE_HTTPS_ERROR_INTERNAL = 0x80435063,
	SCE_HTTPS_ERROR_PROXY = 0x80435064,
	SCE_SSL_ERROR_INVALID_PARAMETER = 0x804351FE
};

enum PSPHttpMethod {
	PSP_HTTP_METHOD_GET,
	PSP_HTTP_METHOD_POST,
	PSP_HTTP_METHOD_HEAD
};

enum SceHttpStatusCode {
	SCE_HTTP_STATUS_CODE_CONTINUE = 100,
	SCE_HTTP_STATUS_CODE_SWITCHING_PROTOCOLS = 101,
	SCE_HTTP_STATUS_CODE_PROCESSING = 102,
	SCE_HTTP_STATUS_CODE_OK = 200,
	SCE_HTTP_STATUS_CODE_CREATED = 201,
	SCE_HTTP_STATUS_CODE_ACCEPTED = 202,
	SCE_HTTP_STATUS_CODE_NON_AUTHORITATIVE_INFORMATION = 203,
	SCE_HTTP_STATUS_CODE_NO_CONTENT = 204,
	SCE_HTTP_STATUS_CODE_RESET_CONTENT = 205,
	SCE_HTTP_STATUS_CODE_PARTIAL_CONTENT = 206,
	SCE_HTTP_STATUS_CODE_MULTI_STATUS = 207,
	SCE_HTTP_STATUS_CODE_MULTIPLE_CHOICES = 300,
	SCE_HTTP_STATUS_CODE_MOVED_PERMANENTLY = 301,
	SCE_HTTP_STATUS_CODE_FOUND = 302,
	SCE_HTTP_STATUS_CODE_SEE_OTHER = 303,
	SCE_HTTP_STATUS_CODE_NOT_MODIFIED = 304,
	SCE_HTTP_STATUS_CODE_USE_PROXY = 305,
	SCE_HTTP_STATUS_CODE_TEMPORARY_REDIRECT = 307,
	SCE_HTTP_STATUS_CODE_BAD_REQUEST = 400,
	SCE_HTTP_STATUS_CODE_UNAUTHORIZED = 401,
	SCE_HTTP_STATUS_CODE_PAYMENT_REQUIRED = 402,
	SCE_HTTP_STATUS_CODE_FORBIDDDEN = 403,
	SCE_HTTP_STATUS_CODE_NOT_FOUND = 404,
	SCE_HTTP_STATUS_CODE_METHOD_NOT_ALLOWED = 405,
	SCE_HTTP_STATUS_CODE_NOT_ACCEPTABLE = 406,
	SCE_HTTP_STATUS_CODE_PROXY_AUTHENTICATION_REQUIRED = 407,
	SCE_HTTP_STATUS_CODE_REQUEST_TIME_OUT = 408,
	SCE_HTTP_STATUS_CODE_CONFLICT = 409,
	SCE_HTTP_STATUS_CODE_GONE = 410,
	SCE_HTTP_STATUS_CODE_LENGTH_REQUIRED = 411,
	SCE_HTTP_STATUS_CODE_PRECONDITION_FAILED = 412,
	SCE_HTTP_STATUS_CODE_REQUEST_ENTITY_TOO_LARGE = 413,
	SCE_HTTP_STATUS_CODE_REQUEST_URI_TOO_LARGE = 414,
	SCE_HTTP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE = 415,
	SCE_HTTP_STATUS_CODE_REQUEST_RANGE_NOT_SATISFIBLE = 416,
	SCE_HTTP_STATUS_CODE_EXPECTATION_FAILED = 417,
	SCE_HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY = 422,
	SCE_HTTP_STATUS_CODE_LOCKED = 423,
	SCE_HTTP_STATUS_CODE_FAILED_DEPENDENCY = 424,
	SCE_HTTP_STATUS_CODE_UPGRADE_REQUIRED = 426,
	SCE_HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR = 500,
	SCE_HTTP_STATUS_CODE_NOT_IMPLEMENTED = 501,
	SCE_HTTP_STATUS_CODE_BAD_GATEWAY = 502,
	SCE_HTTP_STATUS_CODE_SERVICE_UNAVAILABLE = 503,
	SCE_HTTP_STATUS_CODE_GATEWAY_TIME_OUT = 504,
	SCE_HTTP_STATUS_CODE_HTTP_VERSION_NOT_SUPPORTED = 505,
	SCE_HTTP_STATUS_CODE_INSUFFICIENT_STORAGE = 507
};

enum SceHttpVersion {
	SCE_HTTP_VERSION_1_0 = 1,
	SCE_HTTP_VERSION_1_1
};

enum SceHttpProxyMode {
	SCE_HTTP_PROXY_AUTO,
	SCE_HTTP_PROXY_MANUAL
};

enum SceHttpAddHeaderMode {
	SCE_HTTP_HEADER_OVERWRITE,
	SCE_HTTP_HEADER_ADD
};

static const char* name_HTTPTemplate = "HTTPTemplate";
static const char* name_HTTPConnection = "HTTPConnection";
static const char* name_HTTPRequest = "HTTPRequest";

class HTTPTemplate {
protected:
	std::string userAgent;
	SceHttpVersion httpVer = SCE_HTTP_VERSION_1_0;
	SceHttpProxyMode autoProxyConf = SCE_HTTP_PROXY_AUTO;
	int useCookie = 0;
	int useKeepAlive = 0;
	int useCache = 0;
	int useAuth = 0;
	int useRedirect = 0;
	u32 connectTimeout = SCE_HTTP_DEFAULT_CONNECT_TIMEOUT;
	u32 sendTimeout = SCE_HTTP_DEFAULT_SEND_TIMEOUT;
	u32 recvTimeout = SCE_HTTP_DEFAULT_RECV_TIMEOUT;
	u32 resolveTimeout = SCE_HTTP_DEFAULT_RESOLVER_TIMEOUT;
	int resolveRetryCount = SCE_HTTP_DEFAULT_RESOLVER_RETRY;
	std::map<std::string, std::string> requestHeaders_;

public:
	HTTPTemplate() {}
	HTTPTemplate(const char* userAgent, int httpVer, int autoProxyConf);
	virtual ~HTTPTemplate() = default;
	virtual const char* className() { return name_HTTPTemplate; }
	const std::string getUserAgent() { return userAgent; }
	int getHttpVer() { return httpVer; }
	int getAutoProxyConf() { return autoProxyConf; }
	u32 getConnectTimeout() { return connectTimeout; }
	u32 getSendTimeout() { return sendTimeout; }
	u32 getRecvTimeout() { return recvTimeout; }
	u32 getResolveTimeout() { return resolveTimeout; }
	int getResolveRetryCount() { return resolveRetryCount; }
	void setUserAgent(const char* userAgent) { this->userAgent = userAgent ? userAgent : ""; }
	void setConnectTimeout(u32 timeout) { this->connectTimeout = timeout; }
	void setSendTimeout(u32 timeout) { this->sendTimeout = timeout; }
	void setRecvTimeout(u32 timeout) { this->recvTimeout = timeout; }
	void setResolveTimeout(u32 timeout) { this->resolveTimeout = timeout; }
	void setResolveRetry(u32 retryCount) { this->resolveRetryCount = retryCount; }
	int addRequestHeader(const char* name, const char* value, u32 mode);
	int removeRequestHeader(const char* name);
};

class HTTPConnection : public HTTPTemplate {
protected:
	int templateID = 0;
	std::string hostString;
	std::string scheme;
	u16 port = 80;
	int enableKeepalive = 0;

public:
	HTTPConnection() {}
	HTTPConnection(int templateID, const char* hostString, const char* scheme, u32 port, int enableKeepalive);
	virtual ~HTTPConnection() = default;

	HTTPConnection& operator=(const HTTPConnection& other) {
		if (this == &other)
			return *this;

		HTTPTemplate::operator=(other);
		templateID = other.templateID;
		hostString = other.hostString;
		scheme = other.scheme;
		port = other.port;
		enableKeepalive = other.enableKeepalive;

		// FTB3's HTTPS endpoint is the SVO HTTP port + 1. Older shim code could
		// leave the connection object carrying 10060 while the request still had an
		// HTTPS scheme. Normalize either representation to the internal legacy-TLS
		// sentinel so request dispatch cannot accidentally fall through to the old
		// plaintext 10060 path.
		if (scheme == "https" && (port == 10060 || port == 10061 || port == http::LegacyFTB3Client::kFTB3LegacySentinelPort))
			port = http::LegacyFTB3Client::kFTB3LegacySentinelPort;

		return *this;
	}

	virtual const char* className() override { return name_HTTPConnection; }
	int getTemplateID() { return templateID; }
	const std::string getHost() { return hostString; }
	const std::string getScheme() { return scheme; }
	u16 getPort() { return port; }
	int getKeepAlive() { return enableKeepalive; }
};

class FTB3RequestURL : public std::string {
public:
	using std::string::string;

	FTB3RequestURL& operator=(const char *value) {
		std::string::operator=(value ? value : "");
		if (rfind("https://", 0) == 0) {
			// Accept either form observed during shim development. HTTPS is the
			// deciding signal; both are normalized to the internal TLS sentinel.
			for (const std::string marker : { std::string(":10061/FTB3_XML/"), std::string(":10060/FTB3_XML/") }) {
				const size_t pos = find(marker);
				if (pos != npos) {
					replace(pos, 6, ":10063");
					break;
				}
			}
		}
		return *this;
	}
};

class HTTPRequest : public HTTPConnection {
private:
	int connectionID;
	int method;
	u64 contentLength;
	FTB3RequestURL url;
	u32 headerAddr_ = 0;
	u32 headerSize_ = 0;
	bool cancelled_ = false;
	int responseCode_ = -1;
	int entityLength_ = -1;
	http::LegacyFTB3Client client;
	std::vector<std::string> responseHeaders_;
	std::string httpLine_;
	std::string responseContent_;

public:
	HTTPRequest(int connectionID, int method, const char* url, u64 contentLength, net::ResolveFunc customResolver);
	~HTTPRequest();
	virtual const char* className() override { return name_HTTPRequest; }
	void setInternalHeaderAddr(u32 addr) { headerAddr_ = addr; }
	int getConnectionID() { return connectionID; }
	int getResponseRemainingContentLength() { return (int)responseContent_.size(); }
	int getResponseContentLength();
	int abortRequest();
	int getStatusCode();
	int getAllResponseHeaders(u32 headerAddrPtr, u32 headerSizePtr);
	int readData(u32 destDataPtr, u32 size);
	int sendRequest(u32 postDataPtr, u32 postDataSize);
};

// FTB3 HTTPS compatibility state.
//
// PPSSPP's sceHttps entry points historically returned success while discarding
// all PSP-visible state. FTB3 calls these entry points as a real lifecycle, so
// keep the state the game establishes instead of treating the calls as no-ops.
// This first pass deliberately does not alter MultiServer or certificate policy;
// it gives the emulator a coherent HTTPS state that the transport can consume.
struct FTB3HttpsCompatState {
	bool initialized = false;
	bool defaultCertLoaded = false;
	bool systemCookieLoaded = false;
	bool systemCookieDirty = false;
	u32 initArg1 = 0;
	u32 initArg2 = 0;
	u32 initArg3 = 0;
	u32 initArg4 = 0;
	u32 certArg1 = 0;
	u32 certArg2 = 0;
	u32 sslOptions = 0x3F;
	int sslCallbackId = 0;
	u32 sslCallbackFunc = 0;
	u32 sslCallbackArg = 0;
	int lastSslError = 0;
	u32 lastSslDetail = 0;
};

inline FTB3HttpsCompatState g_ftb3HttpsCompatState;

// These are defined in sceHttp.cpp and remain the canonical module flags.
extern bool httpInited;
extern bool httpsInited;

// Real compatibility implementations used by FTB3. Function-like macro aliases
// below rename PPSSPP's old static no-op definitions inside sceHttp.cpp while
// leaving the HLE registration table bound to these implementations.
static inline int sceHttpsInit(int arg1, int arg2, int arg3, int arg4) {
	if (httpsInited)
		return SCE_SSL_ERROR_ALREADY_INIT;

	g_ftb3HttpsCompatState = {};
	g_ftb3HttpsCompatState.initialized = true;
	g_ftb3HttpsCompatState.initArg1 = static_cast<u32>(arg1);
	g_ftb3HttpsCompatState.initArg2 = static_cast<u32>(arg2);
	g_ftb3HttpsCompatState.initArg3 = static_cast<u32>(arg3);
	g_ftb3HttpsCompatState.initArg4 = static_cast<u32>(arg4);
	g_ftb3HttpsCompatState.sslOptions = 0x3F;
	httpsInited = true;

	ERROR_LOG(Log::sceNet, "[FTB3 HTTPS] sceHttpsInit state created args=%08x,%08x,%08x,%08x options=%02x",
		g_ftb3HttpsCompatState.initArg1, g_ftb3HttpsCompatState.initArg2,
		g_ftb3HttpsCompatState.initArg3, g_ftb3HttpsCompatState.initArg4,
		g_ftb3HttpsCompatState.sslOptions);
	return 0;
}

static inline int sceHttpsInitWithPath(int arg1, int arg2, int arg3) {
	if (httpsInited)
		return SCE_SSL_ERROR_ALREADY_INIT;

	g_ftb3HttpsCompatState = {};
	g_ftb3HttpsCompatState.initialized = true;
	g_ftb3HttpsCompatState.initArg1 = static_cast<u32>(arg1);
	g_ftb3HttpsCompatState.initArg2 = static_cast<u32>(arg2);
	g_ftb3HttpsCompatState.initArg3 = static_cast<u32>(arg3);
	g_ftb3HttpsCompatState.sslOptions = 0x3F;
	httpsInited = true;

	ERROR_LOG(Log::sceNet, "[FTB3 HTTPS] sceHttpsInitWithPath state created args=%08x,%08x,%08x options=%02x",
		g_ftb3HttpsCompatState.initArg1, g_ftb3HttpsCompatState.initArg2,
		g_ftb3HttpsCompatState.initArg3, g_ftb3HttpsCompatState.sslOptions);
	return 0;
}

static inline int sceHttpsEnd() {
	if (!httpsInited)
		return SCE_SSL_ERROR_NOT_INIT;

	ERROR_LOG(Log::sceNet,
		"[FTB3 HTTPS] sceHttpsEnd certLoaded=%d cookieLoaded=%d callback=%08x lastError=%08x detail=%08x",
		g_ftb3HttpsCompatState.defaultCertLoaded ? 1 : 0,
		g_ftb3HttpsCompatState.systemCookieLoaded ? 1 : 0,
		g_ftb3HttpsCompatState.sslCallbackFunc,
		static_cast<u32>(g_ftb3HttpsCompatState.lastSslError),
		g_ftb3HttpsCompatState.lastSslDetail);

	g_ftb3HttpsCompatState = {};
	httpsInited = false;
	return 0;
}

static inline int sceHttpsLoadDefaultCert(int arg1, int arg2) {
	if (!httpsInited)
		return SCE_SSL_ERROR_NOT_INIT;

	g_ftb3HttpsCompatState.defaultCertLoaded = true;
	g_ftb3HttpsCompatState.certArg1 = static_cast<u32>(arg1);
	g_ftb3HttpsCompatState.certArg2 = static_cast<u32>(arg2);
	ERROR_LOG(Log::sceNet, "[FTB3 HTTPS] default certificate set loaded args=%08x,%08x",
		g_ftb3HttpsCompatState.certArg1, g_ftb3HttpsCompatState.certArg2);
	return 0;
}

static inline int sceHttpsSetSslCallback(int id, u32 callbackFuncPtr, u32 userArgPtr) {
	if (!httpsInited)
		return SCE_SSL_ERROR_NOT_INIT;

	g_ftb3HttpsCompatState.sslCallbackId = id;
	g_ftb3HttpsCompatState.sslCallbackFunc = callbackFuncPtr;
	g_ftb3HttpsCompatState.sslCallbackArg = userArgPtr;
	ERROR_LOG(Log::sceNet, "[FTB3 HTTPS] SSL callback %s id=%d func=%08x arg=%08x",
		callbackFuncPtr ? "registered" : "cleared", id, callbackFuncPtr, userArgPtr);
	return 0;
}

static inline int sceHttpsDisableOption(int flags) {
	if (!httpsInited)
		return SCE_SSL_ERROR_NOT_INIT;

	g_ftb3HttpsCompatState.sslOptions &= ~static_cast<u32>(flags);
	ERROR_LOG(Log::sceNet, "[FTB3 HTTPS] disabled SSL option flags=%08x -> active=%08x",
		static_cast<u32>(flags), g_ftb3HttpsCompatState.sslOptions);
	return 0;
}

static inline int sceHttpLoadSystemCookie() {
	g_ftb3HttpsCompatState.systemCookieLoaded = true;
	g_ftb3HttpsCompatState.systemCookieDirty = false;
	ERROR_LOG(Log::sceNet, "[FTB3 HTTPS] system cookie store loaded (in-memory compatibility state)");
	return 0;
}

static inline int sceHttpSaveSystemCookie() {
	if (!g_ftb3HttpsCompatState.systemCookieLoaded)
		return SCE_HTTP_ERROR_BEFORE_COOKIE_LOAD;

	g_ftb3HttpsCompatState.systemCookieDirty = false;
	ERROR_LOG(Log::sceNet, "[FTB3 HTTPS] system cookie store saved (in-memory compatibility state)");
	return 0;
}

// sceHttp.cpp still contains the original placeholder implementations. Rename
// only function definitions/calls that use parentheses; registration entries use
// bare function identifiers and therefore continue to bind to the functions above.
#define sceHttpsInit(...) sceHttpsInit_PPSSPP_placeholder(__VA_ARGS__)
#define sceHttpsInitWithPath(...) sceHttpsInitWithPath_PPSSPP_placeholder(__VA_ARGS__)
#define sceHttpsEnd(...) sceHttpsEnd_PPSSPP_placeholder(__VA_ARGS__)
#define sceHttpsLoadDefaultCert(...) sceHttpsLoadDefaultCert_PPSSPP_placeholder(__VA_ARGS__)
#define sceHttpsSetSslCallback(...) sceHttpsSetSslCallback_PPSSPP_placeholder(__VA_ARGS__)
#define sceHttpsDisableOption(...) sceHttpsDisableOption_PPSSPP_placeholder(__VA_ARGS__)
#define sceHttpLoadSystemCookie(...) sceHttpLoadSystemCookie_PPSSPP_placeholder(__VA_ARGS__)
#define sceHttpSaveSystemCookie(...) sceHttpSaveSystemCookie_PPSSPP_placeholder(__VA_ARGS__)

void __HttpInit();
void __HttpShutdown();
void Register_sceHttp();
