#pragma once

#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "Common/Log.h"
#include "Common/Net/HTTPClient.h"
#include "Common/Net/LegacySSL3.h"

namespace http {

// FTB3-only HTTP client shim for the PPSSPP compatibility branch.
// Port 10063 is an internal sentinel used by sceHttp to avoid the old
// 10061 -> 10060 plaintext rewrite. It is never contacted on the network;
// Resolve() converts it back to FTB3's real SSL endpoint on 10061.
class LegacyFTB3Client : public Client {
public:
	explicit LegacyFTB3Client(net::ResolveFunc func) : Client(std::move(func)) {}

	bool Resolve(const char *host, int port, net::DNSType type = net::DNSType::ANY) {
		legacyFTB3_ = port == kFTB3LegacySentinelPort;
		const int networkPort = legacyFTB3_ ? kFTB3SSLPort : port;
		if (legacyFTB3_) {
			// Deliberately ERROR level for the current FTB3 diagnostic pass so this
			// cannot disappear behind normal HTTP/Net log filtering.
			ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client::Resolve selected host=%s requestedPort=%d networkPort=%d",
				host ? host : "", port, networkPort);
		}
		return Client::Resolve(host, networkPort, type);
	}

	bool Connect(int maxTries = 2, double timeout = 20.0f, bool *cancelConnect = nullptr) {
		if (legacyFTB3_) {
			ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client::Connect entering, target network port=%d", kFTB3SSLPort);
		}
		if (!Client::Connect(maxTries, timeout, cancelConnect)) {
			if (legacyFTB3_) {
				ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client::Connect TCP connect failed before SSLv3 handshake");
			}
			return false;
		}
		if (!legacyFTB3_)
			return true;

		ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client TCP connected to port %d; starting SSLv3 handshake", kFTB3SSLPort);
		legacySSL_ = std::make_unique<net::LegacySSL3Client>(sock());
		std::string error;
		if (!legacySSL_->Handshake(&error)) {
			ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client SSLv3 handshake FAILED: %s", error.c_str());
			legacySSL_.reset();
			return false;
		}
		ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client SSLv3 handshake COMPLETED");
		return true;
	}

	void Disconnect() {
		legacySSL_.reset();
		legacyFTB3_ = false;
		responseReady_ = false;
		responseBody_.clear();
		Client::Disconnect();
	}

	int SendRequestWithData(const char *method, const RequestParams &req, std::string_view data, const char *otherHeaders, net::RequestProgress *progress) {
		if (!legacyFTB3_)
			return Client::SendRequestWithData(method, req, data, otherHeaders, progress);
		if (!legacySSL_)
			return -1;

		if (progress)
			progress->Update(0, 0, false);

		ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client HTTP request method=%s resource=%s bodyBytes=%zu",
			method ? method : "", req.resource.c_str(), data.size());

		std::string request;
		request.reserve(512 + data.size());
		request += method;
		request += " ";
		request += req.resource;
		request += " HTTP/";
		request += httpVersion_;
		request += "\r\nHost: ";
		request += host_;
		request += "\r\nUser-Agent: ";
		request += userAgent_;
		request += "\r\nAccept: ";
		request += req.acceptMime;
		request += "\r\nConnection: close\r\n";
		if (otherHeaders)
			request += otherHeaders;
		request += "\r\n";
		request.append(data.data(), data.size());

		std::string error;
		if (!legacySSL_->WriteApplicationData(request, &error)) {
			ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client SSLv3 HTTP write FAILED: %s", error.c_str());
			return -1;
		}
		ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client SSLv3 HTTP write completed");

		responseReady_ = false;
		responseBody_.clear();
		return 0;
	}

	int ReadResponseHeaders(net::Buffer *readbuf, std::vector<std::string> &responseHeaders, net::RequestProgress *progress, std::string *statusLine = nullptr) {
		if (!legacyFTB3_)
			return Client::ReadResponseHeaders(readbuf, responseHeaders, progress, statusLine);
		if (!legacySSL_)
			return -1;

		std::string plaintext;
		std::string error;
		if (!legacySSL_->ReadApplicationData(&plaintext, &error)) {
			ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client SSLv3 HTTP read FAILED: %s", error.c_str());
			return -1;
		}
		ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client received %zu decrypted HTTP byte(s)", plaintext.size());

		const size_t headerEnd = plaintext.find("\r\n\r\n");
		if (headerEnd == std::string::npos) {
			ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client response did not contain a complete HTTP header block");
			return -1;
		}

		const std::string headers = plaintext.substr(0, headerEnd);
		responseBody_ = plaintext.substr(headerEnd + 4);
		responseReady_ = true;

		size_t lineStart = 0;
		size_t lineEnd = headers.find("\r\n");
		std::string firstLine = lineEnd == std::string::npos ? headers : headers.substr(0, lineEnd);
		if (statusLine)
			*statusLine = firstLine;

		ERROR_LOG(Log::sceNet, "[FTB3 TRACE] LegacyFTB3Client HTTP status line: %s", firstLine.c_str());

		const size_t firstSpace = firstLine.find(' ');
		if (firstSpace == std::string::npos) {
			ERROR_LOG(Log::sceNet, "FTB3 SSLv3 response had invalid HTTP status line: %s", firstLine.c_str());
			return -1;
		}
		const int code = std::atoi(firstLine.c_str() + firstSpace + 1);
		if (code <= 0) {
			ERROR_LOG(Log::sceNet, "FTB3 SSLv3 response had invalid HTTP status code: %s", firstLine.c_str());
			return -1;
		}

		lineStart = lineEnd == std::string::npos ? headers.size() : lineEnd + 2;
		while (lineStart < headers.size()) {
			lineEnd = headers.find("\r\n", lineStart);
			if (lineEnd == std::string::npos)
				lineEnd = headers.size();
			if (lineEnd > lineStart)
				responseHeaders.push_back(headers.substr(lineStart, lineEnd - lineStart));
			lineStart = lineEnd + 2;
		}

		if (responseHeaders.empty()) {
			ERROR_LOG(Log::sceNet, "FTB3 SSLv3 response contained no HTTP headers");
			return -1;
		}
		return code;
	}

	int ReadResponseEntity(net::Buffer *readbuf, const std::vector<std::string> &responseHeaders, Buffer *output, net::RequestProgress *progress) {
		if (!legacyFTB3_)
			return Client::ReadResponseEntity(readbuf, responseHeaders, output, progress);
		if (!responseReady_)
			return -1;

		if (!output->IsVoid())
			output->Append(responseBody_);
		if (progress)
			progress->Update(static_cast<int64_t>(responseBody_.size()), static_cast<int64_t>(responseBody_.size()), true);
		responseReady_ = false;
		return 0;
	}

	static constexpr int kFTB3LegacySentinelPort = 10063;
	static constexpr int kFTB3SSLPort = 10061;

private:
	bool legacyFTB3_ = false;
	bool responseReady_ = false;
	std::string responseBody_;
	std::unique_ptr<net::LegacySSL3Client> legacySSL_;
};

}  // namespace http
