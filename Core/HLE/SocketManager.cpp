#include "Common/Net/SocketCompat.h"
#include "Core/HLE/NetInetConstants.h"
#include "Core/HLE/SocketManager.h"
#include "Core/HLE/sceKernelThread.h"
#include "Core/MIPS/MIPS.h"
#include "Common/Log.h"

#include <deque>
#include <mutex>

SocketManager g_socketManager;
static std::mutex g_socketMutex;  // TODO: Remove once the adhoc thread is gone

struct FTB3SocketAccessEntry {
	const char *event = nullptr;
	u32 pc = 0;
	int threadId = 0;
	int peerPort = 0;
};

static std::deque<FTB3SocketAccessEntry> g_ftb3SocketHistory[256];

static int GetSocketPeerPort(SOCKET sock) {
	sockaddr_storage peer{};
#if PPSSPP_PLATFORM(WINDOWS)
	int peerLen = static_cast<int>(sizeof(peer));
#else
	socklen_t peerLen = static_cast<socklen_t>(sizeof(peer));
#endif
	if (getpeername(sock, reinterpret_cast<sockaddr *>(&peer), &peerLen) != 0)
		return 0;

	if (peer.ss_family == AF_INET)
		return ntohs(reinterpret_cast<const sockaddr_in *>(&peer)->sin_port);
#if defined(AF_INET6)
	if (peer.ss_family == AF_INET6)
		return ntohs(reinterpret_cast<const sockaddr_in6 *>(&peer)->sin6_port);
#endif
	return 0;
}

static bool IsFTB3LegacyTLSPeer(SOCKET sock, int *peerPort) {
	const int port = GetSocketPeerPort(sock);
	if (peerPort)
		*peerPort = port;
	return port == 10061;
}

static void RecordFTB3SocketAccess(const char *event, int pspSocket, SOCKET hostSocket) {
	if (pspSocket < 0 || pspSocket >= 256)
		return;

	FTB3SocketAccessEntry entry;
	entry.event = event;
	entry.pc = currentMIPS ? currentMIPS->pc : 0;
	entry.threadId = sceKernelGetThreadId();
	entry.peerPort = GetSocketPeerPort(hostSocket);

	auto &history = g_ftb3SocketHistory[pspSocket];
	history.push_back(entry);
	while (history.size() > 32)
		history.pop_front();
}

static void DumpFTB3SocketHistory(int pspSocket, SOCKET hostSocket) {
	if (pspSocket < 0 || pspSocket >= 256)
		return;

	const int peerPort = GetSocketPeerPort(hostSocket);
	if (peerPort != 10061)
		return;

	const auto &history = g_ftb3SocketHistory[pspSocket];
	ERROR_LOG(Log::sceNet,
		"[FTB3 WIRE] HISTORY_BEGIN pspSocket=%d hostSocket=%llu entries=%zu peerPort=%d",
		pspSocket, static_cast<unsigned long long>(hostSocket), history.size(), peerPort);
	for (size_t i = 0; i < history.size(); ++i) {
		const auto &entry = history[i];
		ERROR_LOG(Log::sceNet,
			"[FTB3 WIRE] HISTORY[%02zu] event=%s pc=%08x thread=%d peerPortAtCall=%d",
			i, entry.event ? entry.event : "?", entry.pc, entry.threadId, entry.peerPort);
	}
	ERROR_LOG(Log::sceNet, "[FTB3 WIRE] HISTORY_END pspSocket=%d", pspSocket);
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
			g_ftb3SocketHistory[i].clear();
			RecordFTB3SocketAccess("CREATE", i, hostSock);
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
			g_ftb3SocketHistory[i].clear();
			RecordFTB3SocketAccess("ADOPT", i, hostSocket);
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
	RecordFTB3SocketAccess("CLOSE_REQUEST", pspSocket, inetSocket->sock);
	DumpFTB3SocketHistory(pspSocket, inetSocket->sock);
	TraceFTB3RawSocket("CLOSE", pspSocket, inetSocket->sock);

	if (closesocket(inetSocket->sock) != 0) {
		ERROR_LOG(Log::sceNet, "closesocket(%d) failed", inetSocket->sock);
		return false;
	}
	inetSocket->state = SocketState::Unused;
	inetSocket->sock = 0;
	if (pspSocket >= 0 && pspSocket < 256)
		g_ftb3SocketHistory[pspSocket].clear();
	return true;
}

bool SocketManager::GetInetSocket(int sock, InetSocket **inetSocket) {
	std::lock_guard<std::mutex> guard(g_socketMutex);
	if (sock < MIN_VALID_INET_SOCKET || sock >= ARRAY_SIZE(inetSockets_) || inetSockets_[sock].state == SocketState::Unused) {
		*inetSocket = nullptr;
		return false;
	}
	*inetSocket = inetSockets_ + sock;

	// Record every PSP-side raw socket lookup, even before connect() has assigned
	// a peer. If this socket later turns out to be FTB3's 10061 connection, the
	// close/term dump will reveal the exact guest PCs that touched it.
	RecordFTB3SocketAccess("GET_INET", sock, (*inetSocket)->sock);
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
	RecordFTB3SocketAccess("HOST_LOOKUP", sock, inetSockets_[sock].sock);
	TraceFTB3RawSocket("HOST_LOOKUP", sock, inetSockets_[sock].sock);
	return inetSockets_[sock].sock;
}

void SocketManager::CloseAll() {
	for (int i = 0; i < ARRAY_SIZE(inetSockets_); ++i) {
		auto &sock = inetSockets_[i];
		if (sock.state != SocketState::Unused) {
			RecordFTB3SocketAccess("CLOSE_ALL_REQUEST", i, sock.sock);
			DumpFTB3SocketHistory(i, sock.sock);
			TraceFTB3RawSocket("CLOSE_ALL", i, sock.sock);
			closesocket(sock.sock);
		}
		sock.state = SocketState::Unused;
		sock.sock = 0;
		if (i < 256)
			g_ftb3SocketHistory[i].clear();
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
