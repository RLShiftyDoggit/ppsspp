#include "Common/Net/SocketCompat.h"
#include "Core/HLE/NetInetConstants.h"
#include "Core/HLE/SocketManager.h"
#include "Core/HLE/sceKernelThread.h"
#include "Core/MIPS/MIPS.h"
#include "Common/Log.h"

#include <mutex>

SocketManager g_socketManager;
static std::mutex g_socketMutex;  // TODO: Remove once the adhoc thread is gone

static bool IsFTB3LegacyTLSPeer(SOCKET sock, int *peerPort) {
	sockaddr_storage peer{};
#if PPSSPP_PLATFORM(WINDOWS)
	int peerLen = static_cast<int>(sizeof(peer));
#else
	socklen_t peerLen = static_cast<socklen_t>(sizeof(peer));
#endif
	if (getpeername(sock, reinterpret_cast<sockaddr *>(&peer), &peerLen) != 0)
		return false;

	int port = 0;
	if (peer.ss_family == AF_INET) {
		port = ntohs(reinterpret_cast<const sockaddr_in *>(&peer)->sin_port);
	}
#if defined(AF_INET6)
	else if (peer.ss_family == AF_INET6) {
		port = ntohs(reinterpret_cast<const sockaddr_in6 *>(&peer)->sin6_port);
	}
#endif
	if (peerPort)
		*peerPort = port;
	return port == 10061;
}

static void TraceFTB3RawSocket(const char *event, int pspSocket, SOCKET hostSocket) {
	int peerPort = 0;
	if (!IsFTB3LegacyTLSPeer(hostSocket, &peerPort))
		return;

	const u32 pc = currentMIPS ? currentMIPS->pc : 0;
	const int threadId = sceKernelGetThreadId();
	ERROR_LOG(Log::sceNet,
		"[FTB3 WIRE] %s pspSocket=%d hostSocket=%llu pc=%08x thread=%d peerPort=%d",
		event,
		pspSocket,
		static_cast<unsigned long long>(hostSocket),
		pc,
		threadId,
		peerPort);
}

InetSocket *SocketManager::CreateSocket(int *index, int *returned_errno, SocketState state, int domain, int type, int protocol) {
	_dbg_assert_(state != SocketState::Unused);

	int hostDomain = convertSocketDomainPSP2Host(domain);
	int hostType = convertSocketTypePSP2Host(type);
	int hostProtocol = convertSocketProtoPSP2Host(protocol);

	SOCKET hostSock = ::socket(hostDomain, hostType, hostProtocol);
	if (hostSock < 0) {
		*returned_errno = socket_errno;
		return nullptr;
	}

	std::lock_guard<std::mutex> guard(g_socketMutex);

	for (int i = MIN_VALID_INET_SOCKET; i < ARRAY_SIZE(inetSockets_); i++) {
		if (inetSockets_[i].state == SocketState::Unused) {
			*index = i;
			InetSocket *inetSock = inetSockets_ + i;
			*inetSock = {};  // Reset to default.
			inetSock->sock = hostSock;
			inetSock->state = state;
			inetSock->domain = domain;
			inetSock->type = type;
			inetSock->protocol = protocol;
			inetSock->nonblocking = false;
			*returned_errno = 0;
			return inetSock;
		}
	}
	_dbg_assert_(false);

	ERROR_LOG(Log::sceNet, "Ran out of socket handles! This is BAD.");
	closesocket(hostSock);
	*returned_errno = ENOMEM; // or something..
	return nullptr;
}

InetSocket *SocketManager::AdoptSocket(int *index, SOCKET hostSocket, const InetSocket *derive) {
	std::lock_guard<std::mutex> guard(g_socketMutex);

	for (int i = MIN_VALID_INET_SOCKET; i < ARRAY_SIZE(inetSockets_); i++) {
		if (inetSockets_[i].state == SocketState::Unused) {
			*index = i;

			InetSocket *inetSock = inetSockets_ + i;
			inetSock->sock = hostSocket;
			inetSock->state = derive->state;
			inetSock->domain = derive->domain;
			inetSock->type = derive->type;
			inetSock->protocol = derive->protocol;
			inetSock->nonblocking = derive->nonblocking;  // should we inherit blocking state?
			return inetSock;
		}
	}

	// No space? Return nullptr and let the caller handle it. Shouldn't ever happen.
	*index = 0;
	return nullptr;
}

bool SocketManager::Close(InetSocket *inetSocket) {
	_dbg_assert_(inetSocket->state != SocketState::Unused);

	int pspSocket = -1;
	for (int i = MIN_VALID_INET_SOCKET; i < ARRAY_SIZE(inetSockets_); ++i) {
		if (&inetSockets_[i] == inetSocket) {
			pspSocket = i;
			break;
		}
	}
	TraceFTB3RawSocket("CLOSE", pspSocket, inetSocket->sock);

	if (closesocket(inetSocket->sock) != 0) {
		ERROR_LOG(Log::sceNet, "closesocket(%d) failed", inetSocket->sock);
		return false;
	}
	inetSocket->state = SocketState::Unused;
	inetSocket->sock = 0;
	return true;
}

bool SocketManager::GetInetSocket(int sock, InetSocket **inetSocket) {
	std::lock_guard<std::mutex> guard(g_socketMutex);
	if (sock < MIN_VALID_INET_SOCKET || sock >= ARRAY_SIZE(inetSockets_) || inetSockets_[sock].state == SocketState::Unused) {
		*inetSocket = nullptr;
		return false;
	}
	*inetSocket = inetSockets_ + sock;

	// Diagnostic only. Every raw sceNetInet send/recv/shutdown/close path first
	// resolves the PSP socket here. If the socket is already connected to FTB3's
	// TLS companion port, preserve the exact guest PC/thread that touched it.
	TraceFTB3RawSocket("ACCESS", sock, (*inetSocket)->sock);
	return true;
}

// Simplified mappers, only really useful in select/poll
SOCKET SocketManager::GetHostSocketFromInetSocket(int sock) {
	std::lock_guard<std::mutex> guard(g_socketMutex);
	if (sock < MIN_VALID_INET_SOCKET || sock >= ARRAY_SIZE(inetSockets_) || inetSockets_[sock].state == SocketState::Unused) {
		_dbg_assert_(false);
		return -1;
	}
	if (sock == 0) {
		// Map 0 to 0, special case.
		return 0;
	}
	TraceFTB3RawSocket("HOST_LOOKUP", sock, inetSockets_[sock].sock);
	return inetSockets_[sock].sock;
}

void SocketManager::CloseAll() {
	for (int i = 0; i < ARRAY_SIZE(inetSockets_); ++i) {
		auto &sock = inetSockets_[i];
		if (sock.state != SocketState::Unused) {
			TraceFTB3RawSocket("CLOSE_ALL", i, sock.sock);
			closesocket(sock.sock);
		}
		sock.state = SocketState::Unused;
		sock.sock = 0;
	}
}

const char *SocketStateToString(SocketState state) {
	switch (state) {
	case SocketState::Unused: return "unused";
	case SocketState::UsedNetInet: return "netInet";
	case SocketState::UsedProAdhoc: return "proAdhoc";
	default:
		return "N/A";
	}
}
