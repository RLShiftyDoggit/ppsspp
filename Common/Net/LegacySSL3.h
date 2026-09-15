#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

#include "ppsspp_config.h"
#include "Common/Crypto/md5.h"
#include "Common/Crypto/sha1.h"
#include "Common/File/FileDescriptor.h"
#include "Common/Net/SocketCompat.h"

#if PPSSPP_PLATFORM(WINDOWS)
#include <bcrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace net {

// Narrow legacy SSL 3.0 client used only by title-specific compatibility code.
// It intentionally implements exactly the transport profile required by FTB3:
//   SSL 3.0 + RSA key exchange + RC4-128 + MD5 record MAC.
// This is not a general-purpose TLS implementation and must never be enabled
// for normal HTTPS traffic.
class LegacySSL3Client {
public:
	explicit LegacySSL3Client(uintptr_t sock) : sock_(sock) {}

	bool Handshake(std::string *error) {
#if PPSSPP_PLATFORM(WINDOWS)
		Reset();

		if (!FillRandom(clientRandom_.data(), clientRandom_.size()))
			return Fail(error, "BCryptGenRandom failed while creating ClientHello random");

		const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
		clientRandom_[0] = static_cast<uint8_t>(now >> 24);
		clientRandom_[1] = static_cast<uint8_t>(now >> 16);
		clientRandom_[2] = static_cast<uint8_t>(now >> 8);
		clientRandom_[3] = static_cast<uint8_t>(now);

		std::vector<uint8_t> clientHelloBody;
		clientHelloBody.reserve(41);
		clientHelloBody.push_back(0x03);
		clientHelloBody.push_back(0x00);
		clientHelloBody.insert(clientHelloBody.end(), clientRandom_.begin(), clientRandom_.end());
		clientHelloBody.push_back(0x00);  // Session ID length.
		clientHelloBody.push_back(0x00);
		clientHelloBody.push_back(0x02);  // Cipher suite vector length.
		clientHelloBody.push_back(0x00);
		clientHelloBody.push_back(0x04);  // SSL_RSA_WITH_RC4_128_MD5.
		clientHelloBody.push_back(0x01);  // Compression methods length.
		clientHelloBody.push_back(0x00);  // null compression.

		std::vector<uint8_t> clientHello = MakeHandshakeMessage(0x01, clientHelloBody);
		AppendTranscript(clientHello);
		if (!SendPlainRecord(kRecordHandshake, clientHello, error))
			return false;

		bool gotServerHello = false;
		bool gotCertificate = false;
		bool gotServerHelloDone = false;
		std::vector<uint8_t> handshakePending;
		std::vector<uint8_t> certificateDer;

		while (!gotServerHelloDone) {
			uint8_t type = 0;
			std::vector<uint8_t> fragment;
			ReadResult rr = ReadRawRecord(&type, &fragment, error);
			if (rr != ReadResult::OK)
				return false;

			if (type == kRecordAlert)
				return FailAlert(fragment, error, "during server hello");
			if (type != kRecordHandshake)
				return Fail(error, "unexpected SSL record before ServerHelloDone");

			handshakePending.insert(handshakePending.end(), fragment.begin(), fragment.end());
			size_t consumed = 0;
			while (handshakePending.size() - consumed >= 4) {
				const uint8_t *msg = handshakePending.data() + consumed;
				const size_t bodyLen = ReadU24(msg + 1);
				const size_t msgLen = 4 + bodyLen;
				if (handshakePending.size() - consumed < msgLen)
					break;

				std::vector<uint8_t> whole(msg, msg + msgLen);
				AppendTranscript(whole);
				const uint8_t *body = msg + 4;

				switch (msg[0]) {
				case 0x02:  // ServerHello.
					if (!ParseServerHello(body, bodyLen, error))
						return false;
					gotServerHello = true;
					break;
				case 0x0B:  // Certificate.
					if (!ExtractLeafCertificate(body, bodyLen, &certificateDer, error))
						return false;
					gotCertificate = true;
					break;
				case 0x0E:  // ServerHelloDone.
					if (bodyLen != 0)
						return Fail(error, "malformed SSLv3 ServerHelloDone");
					gotServerHelloDone = true;
					break;
				default:
					break;
				}

				consumed += msgLen;
			}
			if (consumed != 0)
				handshakePending.erase(handshakePending.begin(), handshakePending.begin() + consumed);
		}

		if (!gotServerHello || !gotCertificate || certificateDer.empty())
			return Fail(error, "SSLv3 server flight was missing ServerHello or Certificate");

		std::array<uint8_t, 48> premaster{};
		premaster[0] = 0x03;
		premaster[1] = 0x00;
		if (!FillRandom(premaster.data() + 2, premaster.size() - 2))
			return Fail(error, "BCryptGenRandom failed while creating premaster secret");

		std::vector<uint8_t> encryptedPremaster;
		if (!EncryptPremaster(certificateDer, premaster, &encryptedPremaster, error))
			return false;

		DeriveSecrets(premaster);
		writeRC4_.Init(clientWriteKey_.data(), clientWriteKey_.size());
		readRC4_.Init(serverWriteKey_.data(), serverWriteKey_.size());

		std::vector<uint8_t> clientKeyExchange = MakeHandshakeMessage(0x10, encryptedPremaster);
		AppendTranscript(clientKeyExchange);
		if (!SendPlainRecord(kRecordHandshake, clientKeyExchange, error))
			return false;

		const std::vector<uint8_t> ccs{ 0x01 };
		if (!SendPlainRecord(kRecordChangeCipherSpec, ccs, error))
			return false;

		writeCipherActive_ = true;
		writeSequence_ = 0;

		std::vector<uint8_t> clientFinishedBody = ComputeFinished("CLNT");
		std::vector<uint8_t> clientFinished = MakeHandshakeMessage(0x14, clientFinishedBody);
		if (!SendProtectedRecord(kRecordHandshake, clientFinished, error))
			return false;
		AppendTranscript(clientFinished);

		bool gotServerCCS = false;
		bool gotServerFinished = false;
		std::vector<uint8_t> serverHandshakePending;
		while (!gotServerFinished) {
			uint8_t type = 0;
			std::vector<uint8_t> fragment;
			ReadResult rr = gotServerCCS ? ReadProtectedRecord(&type, &fragment, error) : ReadRawRecord(&type, &fragment, error);
			if (rr != ReadResult::OK)
				return false;

			if (!gotServerCCS) {
				if (type == kRecordAlert)
					return FailAlert(fragment, error, "before server ChangeCipherSpec");
				if (type != kRecordChangeCipherSpec || fragment.size() != 1 || fragment[0] != 0x01)
					return Fail(error, "expected SSLv3 server ChangeCipherSpec");
				gotServerCCS = true;
				readCipherActive_ = true;
				readSequence_ = 0;
				continue;
			}

			if (type == kRecordAlert)
				return FailAlert(fragment, error, "waiting for server Finished");
			if (type != kRecordHandshake)
				return Fail(error, "unexpected protected SSLv3 record before server Finished");

			serverHandshakePending.insert(serverHandshakePending.end(), fragment.begin(), fragment.end());
			size_t consumed = 0;
			while (serverHandshakePending.size() - consumed >= 4) {
				const uint8_t *msg = serverHandshakePending.data() + consumed;
				const size_t bodyLen = ReadU24(msg + 1);
				const size_t msgLen = 4 + bodyLen;
				if (serverHandshakePending.size() - consumed < msgLen)
					break;

				if (msg[0] == 0x14) {
					std::vector<uint8_t> expected = ComputeFinished("SRVR");
					if (bodyLen != expected.size() || !std::equal(expected.begin(), expected.end(), msg + 4))
						return Fail(error, "SSLv3 server Finished verify_data mismatch");
					std::vector<uint8_t> whole(msg, msg + msgLen);
					AppendTranscript(whole);
					gotServerFinished = true;
				}
				consumed += msgLen;
			}
			if (consumed != 0)
				serverHandshakePending.erase(serverHandshakePending.begin(), serverHandshakePending.begin() + consumed);
		}

		handshakeComplete_ = true;
		return true;
#else
		return Fail(error, "legacy SSLv3 transport is currently implemented only for Windows builds");
#endif
	}

	bool WriteApplicationData(std::string_view data, std::string *error) {
		if (!handshakeComplete_ || !writeCipherActive_)
			return Fail(error, "SSLv3 application write attempted before handshake completion");

		size_t offset = 0;
		while (offset < data.size()) {
			const size_t remaining = data.size() - offset;
			const size_t chunk = remaining > kMaxPlaintext ? kMaxPlaintext : remaining;
			std::vector<uint8_t> fragment(data.begin() + offset, data.begin() + offset + chunk);
			if (!SendProtectedRecord(kRecordApplicationData, fragment, error))
				return false;
			offset += chunk;
		}
		return true;
	}

	bool ReadApplicationData(std::string *out, std::string *error) {
		if (!out)
			return Fail(error, "null output buffer passed to SSLv3 reader");
		if (!handshakeComplete_ || !readCipherActive_)
			return Fail(error, "SSLv3 application read attempted before handshake completion");

		while (true) {
			uint8_t type = 0;
			std::vector<uint8_t> fragment;
			ReadResult rr = ReadProtectedRecord(&type, &fragment, error);
			if (rr == ReadResult::EOF_REACHED)
				return true;
			if (rr != ReadResult::OK)
				return false;

			if (type == kRecordApplicationData) {
				out->append(reinterpret_cast<const char *>(fragment.data()), fragment.size());
				continue;
			}
			if (type == kRecordAlert) {
				if (fragment.size() >= 2 && fragment[1] == 0x00)
					return true;
				return FailAlert(fragment, error, "while reading application data");
			}
		}
	}

private:
	static constexpr uint8_t kRecordChangeCipherSpec = 20;
	static constexpr uint8_t kRecordAlert = 21;
	static constexpr uint8_t kRecordHandshake = 22;
	static constexpr uint8_t kRecordApplicationData = 23;
	static constexpr size_t kMaxPlaintext = 16384;

	enum class ReadResult {
		OK,
		EOF_REACHED,
		ERROR,
	};

	class RC4State {
	public:
		void Init(const uint8_t *key, size_t keyLen) {
			for (size_t i = 0; i < 256; ++i)
				s_[i] = static_cast<uint8_t>(i);
			uint8_t j = 0;
			for (size_t i = 0; i < 256; ++i) {
				j = static_cast<uint8_t>(j + s_[i] + key[i % keyLen]);
				std::swap(s_[i], s_[j]);
			}
			i_ = 0;
			j_ = 0;
		}

		void Process(uint8_t *data, size_t len) {
			for (size_t n = 0; n < len; ++n) {
				i_ = static_cast<uint8_t>(i_ + 1);
				j_ = static_cast<uint8_t>(j_ + s_[i_]);
				std::swap(s_[i_], s_[j_]);
				const uint8_t k = s_[static_cast<uint8_t>(s_[i_] + s_[j_])];
				data[n] ^= k;
			}
		}

	private:
		std::array<uint8_t, 256> s_{};
		uint8_t i_ = 0;
		uint8_t j_ = 0;
	};

	void Reset() {
		handshakeComplete_ = false;
		writeCipherActive_ = false;
		readCipherActive_ = false;
		writeSequence_ = 0;
		readSequence_ = 0;
		transcript_.clear();
	}

	static bool Fail(std::string *error, const char *message) {
		if (error)
			*error = message;
		return false;
	}

	static bool FailAlert(const std::vector<uint8_t> &fragment, std::string *error, const char *where) {
		if (error) {
			if (fragment.size() >= 2)
				*error = "SSLv3 alert " + std::to_string(fragment[1]) + " " + where;
			else
				*error = std::string("malformed SSLv3 alert ") + where;
		}
		return false;
	}

	static size_t ReadU24(const uint8_t *p) {
		return (static_cast<size_t>(p[0]) << 16) | (static_cast<size_t>(p[1]) << 8) | static_cast<size_t>(p[2]);
	}

	static void WriteU24(std::vector<uint8_t> *out, size_t value) {
		out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
		out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
		out->push_back(static_cast<uint8_t>(value & 0xFF));
	}

	static std::vector<uint8_t> MakeHandshakeMessage(uint8_t type, const std::vector<uint8_t> &body) {
		std::vector<uint8_t> out;
		out.reserve(4 + body.size());
		out.push_back(type);
		WriteU24(&out, body.size());
		out.insert(out.end(), body.begin(), body.end());
		return out;
	}

	void AppendTranscript(const std::vector<uint8_t> &message) {
		transcript_.insert(transcript_.end(), message.begin(), message.end());
	}

	static std::array<uint8_t, 16> MD5(const std::vector<uint8_t> &data) {
		std::array<uint8_t, 16> digest{};
		md5_context ctx{};
		ppsspp_md5_starts(&ctx);
		if (!data.empty())
			ppsspp_md5_update(&ctx, const_cast<unsigned char *>(data.data()), static_cast<int>(data.size()));
		ppsspp_md5_finish(&ctx, digest.data());
		return digest;
	}

	static std::array<uint8_t, 20> SHA1(const std::vector<uint8_t> &data) {
		std::array<uint8_t, 20> digest{};
		sha1_context ctx{};
		sha1_starts(&ctx);
		if (!data.empty())
			sha1_update(&ctx, const_cast<unsigned char *>(data.data()), static_cast<int>(data.size()));
		sha1_finish(&ctx, digest.data());
		return digest;
	}

	static void Append(std::vector<uint8_t> *out, const uint8_t *data, size_t len) {
		out->insert(out->end(), data, data + len);
	}

	template <size_t N>
	static void Append(std::vector<uint8_t> *out, const std::array<uint8_t, N> &data) {
		Append(out, data.data(), data.size());
	}

	static std::array<uint8_t, 16> SSL3Mac(const std::array<uint8_t, 16> &secret, uint64_t sequence, uint8_t type, const std::vector<uint8_t> &fragment) {
		std::vector<uint8_t> inner;
		inner.reserve(16 + 48 + 8 + 1 + 2 + fragment.size());
		Append(&inner, secret);
		inner.insert(inner.end(), 48, 0x36);
		for (int shift = 56; shift >= 0; shift -= 8)
			inner.push_back(static_cast<uint8_t>(sequence >> shift));
		inner.push_back(type);
		inner.push_back(static_cast<uint8_t>((fragment.size() >> 8) & 0xFF));
		inner.push_back(static_cast<uint8_t>(fragment.size() & 0xFF));
		inner.insert(inner.end(), fragment.begin(), fragment.end());
		std::array<uint8_t, 16> innerDigest = MD5(inner);

		std::vector<uint8_t> outer;
		outer.reserve(16 + 48 + 16);
		Append(&outer, secret);
		outer.insert(outer.end(), 48, 0x5C);
		Append(&outer, innerDigest);
		return MD5(outer);
	}

	std::vector<uint8_t> ComputeFinished(const char sender[5]) const {
		std::vector<uint8_t> md5Inner;
		md5Inner.reserve(transcript_.size() + 4 + masterSecret_.size() + 48);
		md5Inner.insert(md5Inner.end(), transcript_.begin(), transcript_.end());
		md5Inner.insert(md5Inner.end(), sender, sender + 4);
		Append(&md5Inner, masterSecret_);
		md5Inner.insert(md5Inner.end(), 48, 0x36);
		std::array<uint8_t, 16> md5InnerDigest = MD5(md5Inner);

		std::vector<uint8_t> md5Outer;
		Append(&md5Outer, masterSecret_);
		md5Outer.insert(md5Outer.end(), 48, 0x5C);
		Append(&md5Outer, md5InnerDigest);
		std::array<uint8_t, 16> md5Finished = MD5(md5Outer);

		std::vector<uint8_t> shaInner;
		shaInner.reserve(transcript_.size() + 4 + masterSecret_.size() + 40);
		shaInner.insert(shaInner.end(), transcript_.begin(), transcript_.end());
		shaInner.insert(shaInner.end(), sender, sender + 4);
		Append(&shaInner, masterSecret_);
		shaInner.insert(shaInner.end(), 40, 0x36);
		std::array<uint8_t, 20> shaInnerDigest = SHA1(shaInner);

		std::vector<uint8_t> shaOuter;
		Append(&shaOuter, masterSecret_);
		shaOuter.insert(shaOuter.end(), 40, 0x5C);
		Append(&shaOuter, shaInnerDigest);
		std::array<uint8_t, 20> shaFinished = SHA1(shaOuter);

		std::vector<uint8_t> out;
		out.reserve(36);
		Append(&out, md5Finished);
		Append(&out, shaFinished);
		return out;
	}

	void DeriveSecrets(const std::array<uint8_t, 48> &premaster) {
		std::vector<uint8_t> master;
		master.reserve(48);
		for (size_t i = 0; i < 3; ++i) {
			std::vector<uint8_t> shaInput(i + 1, static_cast<uint8_t>('A' + i));
			Append(&shaInput, premaster);
			Append(&shaInput, clientRandom_);
			Append(&shaInput, serverRandom_);
			std::array<uint8_t, 20> shaDigest = SHA1(shaInput);

			std::vector<uint8_t> md5Input;
			Append(&md5Input, premaster);
			Append(&md5Input, shaDigest);
			std::array<uint8_t, 16> md5Digest = MD5(md5Input);
			master.insert(master.end(), md5Digest.begin(), md5Digest.end());
		}
		std::copy_n(master.begin(), masterSecret_.size(), masterSecret_.begin());

		std::vector<uint8_t> keyBlock;
		for (size_t i = 0; keyBlock.size() < 64; ++i) {
			std::vector<uint8_t> shaInput(i + 1, static_cast<uint8_t>('A' + i));
			Append(&shaInput, masterSecret_);
			Append(&shaInput, serverRandom_);
			Append(&shaInput, clientRandom_);
			std::array<uint8_t, 20> shaDigest = SHA1(shaInput);

			std::vector<uint8_t> md5Input;
			Append(&md5Input, masterSecret_);
			Append(&md5Input, shaDigest);
			std::array<uint8_t, 16> md5Digest = MD5(md5Input);
			keyBlock.insert(keyBlock.end(), md5Digest.begin(), md5Digest.end());
		}

		std::copy_n(keyBlock.begin() + 0, 16, clientMacSecret_.begin());
		std::copy_n(keyBlock.begin() + 16, 16, serverMacSecret_.begin());
		std::copy_n(keyBlock.begin() + 32, 16, clientWriteKey_.begin());
		std::copy_n(keyBlock.begin() + 48, 16, serverWriteKey_.begin());
	}

	bool ParseServerHello(const uint8_t *body, size_t len, std::string *error) {
		if (len < 38)
			return Fail(error, "SSLv3 ServerHello too short");
		if (body[0] != 0x03 || body[1] != 0x00)
			return Fail(error, "server did not negotiate SSL 3.0");
		std::copy_n(body + 2, serverRandom_.size(), serverRandom_.begin());

		const size_t sessionLen = body[34];
		const size_t suiteOffset = 35 + sessionLen;
		if (suiteOffset + 3 > len)
			return Fail(error, "malformed SSLv3 ServerHello session ID");
		if (body[suiteOffset] != 0x00 || body[suiteOffset + 1] != 0x04)
			return Fail(error, "server selected a cipher other than SSL_RSA_WITH_RC4_128_MD5");
		if (body[suiteOffset + 2] != 0x00)
			return Fail(error, "server selected unsupported SSLv3 compression");
		return true;
	}

	static bool ExtractLeafCertificate(const uint8_t *body, size_t len, std::vector<uint8_t> *cert, std::string *error) {
		if (len < 6)
			return Fail(error, "SSLv3 Certificate message too short");
		const size_t listLen = ReadU24(body);
		if (listLen + 3 > len)
			return Fail(error, "malformed SSLv3 certificate_list length");
		const size_t certLen = ReadU24(body + 3);
		if (certLen == 0 || certLen + 6 > len)
			return Fail(error, "malformed SSLv3 leaf certificate length");
		cert->assign(body + 6, body + 6 + certLen);
		return true;
	}

#if PPSSPP_PLATFORM(WINDOWS)
	static bool FillRandom(uint8_t *data, size_t len) {
		return BCryptGenRandom(nullptr, data, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
	}

	static bool EncryptPremaster(const std::vector<uint8_t> &certificateDer, const std::array<uint8_t, 48> &premaster, std::vector<uint8_t> *encrypted, std::string *error) {
		PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certificateDer.data(), static_cast<DWORD>(certificateDer.size()));
		if (!cert)
			return Fail(error, "CertCreateCertificateContext failed for SSLv3 server certificate");

		BCRYPT_KEY_HANDLE key = nullptr;
		const BOOL imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, &key);
		if (!imported || !key) {
			CertFreeCertificateContext(cert);
			return Fail(error, "CryptImportPublicKeyInfoEx2 failed for SSLv3 RSA certificate");
		}

		ULONG outputSize = 0;
		NTSTATUS status = BCryptEncrypt(key, const_cast<PUCHAR>(premaster.data()), static_cast<ULONG>(premaster.size()), nullptr, nullptr, 0, nullptr, 0, &outputSize, BCRYPT_PAD_PKCS1);
		if (status < 0 || outputSize == 0) {
			BCryptDestroyKey(key);
			CertFreeCertificateContext(cert);
			return Fail(error, "BCryptEncrypt size query failed for SSLv3 RSA premaster");
		}

		encrypted->resize(outputSize);
		status = BCryptEncrypt(key, const_cast<PUCHAR>(premaster.data()), static_cast<ULONG>(premaster.size()), nullptr, nullptr, 0, encrypted->data(), outputSize, &outputSize, BCRYPT_PAD_PKCS1);
		BCryptDestroyKey(key);
		CertFreeCertificateContext(cert);
		if (status < 0)
			return Fail(error, "BCryptEncrypt failed for SSLv3 RSA premaster");
		encrypted->resize(outputSize);
		return true;
	}
#else
	static bool FillRandom(uint8_t *, size_t) { return false; }
#endif

	bool SendPlainRecord(uint8_t type, const std::vector<uint8_t> &fragment, std::string *error) {
		if (fragment.size() > 0xFFFF)
			return Fail(error, "SSLv3 record fragment exceeded 65535 bytes");
		std::vector<uint8_t> record;
		record.reserve(5 + fragment.size());
		record.push_back(type);
		record.push_back(0x03);
		record.push_back(0x00);
		record.push_back(static_cast<uint8_t>(fragment.size() >> 8));
		record.push_back(static_cast<uint8_t>(fragment.size()));
		record.insert(record.end(), fragment.begin(), fragment.end());
		return SendAll(record.data(), record.size(), error);
	}

	bool SendProtectedRecord(uint8_t type, const std::vector<uint8_t> &fragment, std::string *error) {
		if (!writeCipherActive_)
			return Fail(error, "attempted protected SSLv3 write before ChangeCipherSpec");
		std::vector<uint8_t> protectedData = fragment;
		std::array<uint8_t, 16> mac = SSL3Mac(clientMacSecret_, writeSequence_, type, fragment);
		protectedData.insert(protectedData.end(), mac.begin(), mac.end());
		writeRC4_.Process(protectedData.data(), protectedData.size());
		++writeSequence_;
		return SendPlainRecord(type, protectedData, error);
	}

	ReadResult ReadRawRecord(uint8_t *type, std::vector<uint8_t> *fragment, std::string *error) {
		uint8_t header[5]{};
		ReadResult rr = ReadExact(header, sizeof(header), error);
		if (rr != ReadResult::OK)
			return rr;
		if (header[1] != 0x03 || header[2] != 0x00) {
			Fail(error, "received non-SSLv3 record version");
			return ReadResult::ERROR;
		}
		const size_t len = (static_cast<size_t>(header[3]) << 8) | header[4];
		if (len > kMaxPlaintext + 2048) {
			Fail(error, "received oversized SSLv3 record");
			return ReadResult::ERROR;
		}
		fragment->resize(len);
		if (len != 0) {
			rr = ReadExact(fragment->data(), len, error);
			if (rr != ReadResult::OK)
				return rr;
		}
		*type = header[0];
		return ReadResult::OK;
	}

	ReadResult ReadProtectedRecord(uint8_t *type, std::vector<uint8_t> *fragment, std::string *error) {
		std::vector<uint8_t> encrypted;
		ReadResult rr = ReadRawRecord(type, &encrypted, error);
		if (rr != ReadResult::OK)
			return rr;
		if (!readCipherActive_) {
			Fail(error, "received protected SSLv3 record before server ChangeCipherSpec");
			return ReadResult::ERROR;
		}
		readRC4_.Process(encrypted.data(), encrypted.size());
		if (encrypted.size() < 16) {
			Fail(error, "protected SSLv3 record was shorter than its MD5 MAC");
			return ReadResult::ERROR;
		}
		fragment->assign(encrypted.begin(), encrypted.end() - 16);
		std::array<uint8_t, 16> expected = SSL3Mac(serverMacSecret_, readSequence_, *type, *fragment);
		if (!std::equal(expected.begin(), expected.end(), encrypted.end() - 16)) {
			Fail(error, "SSLv3 record MD5 MAC verification failed");
			return ReadResult::ERROR;
		}
		++readSequence_;
		return ReadResult::OK;
	}

	bool SendAll(const uint8_t *data, size_t len, std::string *error) {
		size_t sent = 0;
		while (sent < len) {
			const int n = send(static_cast<SOCKET>(sock_), reinterpret_cast<const char *>(data + sent), static_cast<int>(len - sent), MSG_NOSIGNAL);
			if (n > 0) {
				sent += static_cast<size_t>(n);
				continue;
			}
			if (n == 0)
				return Fail(error, "socket closed during SSLv3 write");
			const int err = socket_errno;
			if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
				if (!fd_util::WaitUntilReady(static_cast<int>(sock_), 30.0, true))
					return Fail(error, "SSLv3 socket write timed out");
				continue;
			}
			return Fail(error, "socket error during SSLv3 write");
		}
		return true;
	}

	ReadResult ReadExact(uint8_t *data, size_t len, std::string *error) {
		size_t received = 0;
		while (received < len) {
			const int n = recv(static_cast<SOCKET>(sock_), reinterpret_cast<char *>(data + received), static_cast<int>(len - received), 0);
			if (n > 0) {
				received += static_cast<size_t>(n);
				continue;
			}
			if (n == 0)
				return received == 0 ? ReadResult::EOF_REACHED : (Fail(error, "socket closed mid-record during SSLv3 read"), ReadResult::ERROR);
			const int err = socket_errno;
			if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
				if (!fd_util::WaitUntilReady(static_cast<int>(sock_), 30.0, false)) {
					Fail(error, "SSLv3 socket read timed out");
					return ReadResult::ERROR;
				}
				continue;
			}
			Fail(error, "socket error during SSLv3 read");
			return ReadResult::ERROR;
		}
		return ReadResult::OK;
	}

	uintptr_t sock_ = static_cast<uintptr_t>(-1);
	bool handshakeComplete_ = false;
	bool writeCipherActive_ = false;
	bool readCipherActive_ = false;
	uint64_t writeSequence_ = 0;
	uint64_t readSequence_ = 0;

	std::array<uint8_t, 32> clientRandom_{};
	std::array<uint8_t, 32> serverRandom_{};
	std::array<uint8_t, 48> masterSecret_{};
	std::array<uint8_t, 16> clientMacSecret_{};
	std::array<uint8_t, 16> serverMacSecret_{};
	std::array<uint8_t, 16> clientWriteKey_{};
	std::array<uint8_t, 16> serverWriteKey_{};
	RC4State writeRC4_{};
	RC4State readRC4_{};
	std::vector<uint8_t> transcript_;
};

}  // namespace net
