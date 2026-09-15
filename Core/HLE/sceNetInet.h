#pragma once

#include "ppsspp_config.h"

#include "Core/HLE/HLE.h"
#include "Core/HLE/sceKernelThread.h"
#include "Core/MIPS/MIPS.h"
#include "Core/MemMapHelpers.h"

#include "Common/Log.h"
#include "Common/Net/SocketCompat.h"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <set>
#include <string>

// Using constants instead of numbers for readability reason, since PSP_THREAD_ATTR_KERNEL/USER is located in sceKernelThread.cpp instead of sceKernelThread.h
#ifndef PSP_THREAD_ATTR_KERNEL
#define PSP_THREAD_ATTR_KERNEL 0x00001000
#endif
#ifndef PSP_THREAD_ATTR_USER
#define PSP_THREAD_ATTR_USER 0x80000000
#endif

// Similar to https://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/sys/sys/fd_set.h
#define		PSP_NET_INET_FD_SETSIZE		256		// PSP can support upto 256 fd(s) while the default FD_SETSIZE on Windows is only 64 
#define		PSP_NET_INET_NFDBITS		32		// Default: 32 = sizeof(u32) * 8 (8-bits of each byte) = number of bits for each element in fds_bits
#define		PSP_NET_INET_NFDBITS_SHIFT	5		// 2^5 = 32 
#define		PSP_NET_INET_NFDBITS_MASK	0x1F	// 0x1F = 5 bit mask (NFDBITS - 1)
#define		PSP_NET_INET_FD_MASK		0xFF	// Making sure FD value in the range of 0-255 to prevent out-of-bound

#define		NetInetFD_SET(n, p) \
				((p)->fds_bits[((n) & PSP_NET_INET_FD_MASK)>>PSP_NET_INET_NFDBITS_SHIFT] |= (1 << ((n) & PSP_NET_INET_NFDBITS_MASK))) // (1 << ((n) % PSP_NET_INET_NFDBITS))
#define		NetInetFD_CLR(n, p) \
				((p)->fds_bits[((n) & PSP_NET_INET_FD_MASK)>>PSP_NET_INET_NFDBITS_SHIFT] &= ~(1 << ((n) & PSP_NET_INET_NFDBITS_MASK)))
#define		NetInetFD_ISSET(n, p) \
				((p)->fds_bits[((n) & PSP_NET_INET_FD_MASK)>>PSP_NET_INET_NFDBITS_SHIFT] & (1 << ((n) & PSP_NET_INET_NFDBITS_MASK)))
#define		NetInetFD_ZERO(p) \
				(void)memset((p), 0, sizeof(*(p)))

// There might be padding (padded to 4 bytes) between each cmsghdr? Similar to http://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch14lev1sec6.html#ch14lev1sec6
struct InetCmsghdr {
	s32_le cmsg_len;   // length in bytes, including this structure, includes padding between cmsg_type and cmsg_data[] ?
	s32_le cmsg_level; // originating protocol 
	s32_le cmsg_type;  // protocol-specific type 
	// followed by unsigned char cmsg_data[], there might be 4-bytes padding between cmsg_type and cmsg_data[] ?
};

struct SceNetInetTimeval {
	u32_le tv_sec;         // seconds 
	u32_le tv_usec;        // and microseconds 
};

// No need to pragma/attribute(pack) the below structs, they are following C rules.

// FdSet
struct SceNetInetFdSet {
	u32_le	fds_bits[(PSP_NET_INET_FD_SETSIZE + (PSP_NET_INET_NFDBITS - 1)) / PSP_NET_INET_NFDBITS]; // Default: 8 = ((PSP_NET_INET_FD_SETSIZE(256) + (PSP_NET_INET_NFDBITS-1)) / PSP_NET_INET_NFDBITS(32)) elements of 32-bit array to represents 256(FD_SETSIZE) bits of fd's bitmap
};

// Sockaddr
struct SceNetInetSockaddr {
	uint8_t sa_len; // length of this struct or sa_data only?
	uint8_t sa_family;
	uint8_t sa_data[14]; // up to 14 bytes of data?
};

// Sockaddr_in
struct SceNetInetSockaddrIn {
	uint8_t sin_len; // length of this struct?
	uint8_t sin_family;
	u16_le sin_port; //uint16_t
	u32_le sin_addr; //uint32_t
	uint8_t sin_zero[8]; // zero-filled padding?
};

// Similar to iovec struct on 32-bit platform from BSD's uio.h/_iovec.h
struct SceNetIovec {
	u32_le iov_base;	// Base address (pointer/void* of buffer)
	u32_le iov_len;		// Length
};

// Similar to msghdr struct on 32-bit platform from BSD's socket.h
struct InetMsghdr {
	u32_le msg_name;					// optional address (pointer/void* to sockaddr_in/SceNetInetSockaddrIn/SceNetInetSockaddr struct?)
	u32_le msg_namelen;					// size of optional address 
	u32_le msg_iov;						// pointer to iovec/SceNetIovec (ie. struct iovec*/PSPPointer<SceNetIovec>), scatter/gather array (buffers are concatenated before sent?)
	s32_le msg_iovlen;					// # elements in msg_iov 
	u32_le msg_control;					// pointer (ie. void*/PSPPointer<InetCmsghdr>) to ancillary data (multiple of cmsghdr/InetCmsghdr struct?), see below 
	u32_le msg_controllen;				// ancillary data buffer len, includes padding between each cmsghdr/InetCmsghdr struct?
	s32_le msg_flags;					// flags on received message (ignored on sendmsg?)
};

// Structure used for manipulating linger option
struct SceNetInetLinger {
	s32_le	l_onoff;		// option on/off 
	s32_le	l_linger;		// linger time in seconds 
};

// Polling Event Field
struct SceNetInetPollfd { //similar format to pollfd in 32bit (pollfd in 64bit have different size)
	s32_le fd;
	s16_le events;  // requested events
	s16_le revents; // returned events
};

// TCP & UDP Socket Union (Internal use only)
/*
typedef struct InetSocket {
	s32_le id; // posix socket id
	s32_le domain; // AF_INET/PF_INET/etc
	s32_le type; // SOCK_STREAM/SOCK_DGRAM/etc
	s32_le protocol; // TCP/UDP/etc
	s32_le nonblocking; // non-blocking flag (ie. FIONBIO) to keep track of the blocking mode since Windows doesn't have getter for this
	s32_le so_broadcast; // broadcast flag (ie. SO_BROADCAST) to keep track of the broadcast flag, since we're using fake broadcast
	s32_le tcp_state; // to keep track TCP connection state
} PACK InetSocket;
*/

// ---------------------------------------------------------

class PointerWrap;

extern bool g_netInited;
extern bool netInetInited;
extern bool g_netApctlInited;
extern u32 netApctlState;
extern SceNetApctlInfoInternal netApctlInfo;
extern const char *const defaultNetConfigName;
extern const char *const defaultNetSSID;

// ---------------------------------------------------------------------------
// FTB3 raw 10061 wire trace
// ---------------------------------------------------------------------------
// Wireshark proved that a TCP connection to 10061 is opened and then closed
// without any application payload.  Trace the PSP raw socket HLE directly so
// we can distinguish a guest sceNetInet connection from host-side PPSSPP HTTP
// traffic and capture the guest PC that connects, attempts I/O, and closes.
// No socket behavior is changed here.
inline std::set<int> g_ftb3RawTlsSockets;

static inline u32 FTB3TracePC() {
	return currentMIPS ? currentMIPS->pc : 0;
}

static inline int FTB3TraceThread() {
	return sceKernelGetThreadId();
}

static inline bool FTB3TraceSockaddr10061(u32 sockAddrPtr, std::string *address) {
	if (!sockAddrPtr)
		return false;
	const u8 *raw = Memory::GetPointerOrException(sockAddrPtr);
	const int port = (static_cast<int>(raw[2]) << 8) | raw[3];
	if (address) {
		char temp[64];
		snprintf(temp, sizeof(temp), "%u.%u.%u.%u:%d", raw[4], raw[5], raw[6], raw[7], port);
		*address = temp;
	}
	return port == 10061;
}

static inline std::string FTB3TraceHexPrefix(u32 bufPtr, u32 bufLen) {
	if (!bufPtr || !bufLen)
		return "<empty>";
	const u8 *data = Memory::GetPointerOrException(bufPtr);
	const u32 count = std::min<u32>(bufLen, 32);
	char temp[4];
	std::string out;
	out.reserve(count * 3);
	for (u32 i = 0; i < count; ++i) {
		snprintf(temp, sizeof(temp), "%02X", data[i]);
		if (!out.empty())
			out.push_back(' ');
		out += temp;
	}
	if (count < bufLen)
		out += " ...";
	return out;
}

// Forward declarations for PPSSPP's original static implementations.  The
// function-like macros below rename their definitions inside sceNetInet.cpp;
// HLE registration uses bare identifiers and therefore binds to these wrappers.
static int sceNetInetConnect_PPSSPP_placeholder(int socket, u32 sockAddrPtr, int sockAddrLen);
static int sceNetInetSend_PPSSPP_placeholder(int socket, u32 bufPtr, u32 bufLen, u32 flags);
static int sceNetInetRecv_PPSSPP_placeholder(int socket, u32 bufPtr, u32 bufLen, u32 flags);
static int sceNetInetSendmsg_PPSSPP_placeholder(int socket, u32 msghdrPtr, int flags);
static int sceNetInetRecvmsg_PPSSPP_placeholder(int socket, u32 msghdrPtr, int flags);
static int sceNetInetShutdown_PPSSPP_placeholder(int socket, int how);
static int sceNetInetSocketAbort_PPSSPP_placeholder(int socket);
static int sceNetInetClose_PPSSPP_placeholder(int socket);
static int sceNetInetCloseWithRST_PPSSPP_placeholder(int socket);
static int sceNetInetTerm_PPSSPP_placeholder();

static inline int sceNetInetConnect(int socket, u32 sockAddrPtr, int sockAddrLen) {
	std::string destination;
	const bool ftb3 = FTB3TraceSockaddr10061(sockAddrPtr, &destination);
	if (ftb3) {
		g_ftb3RawTlsSockets.insert(socket);
		ERROR_LOG(Log::sceNet,
			"[FTB3 WIRE] CONNECT enter socket=%d pc=%08x thread=%d dst=%s sockaddr=%08x len=%d",
			socket, FTB3TracePC(), FTB3TraceThread(), destination.c_str(), sockAddrPtr, sockAddrLen);
	}
	const int result = sceNetInetConnect_PPSSPP_placeholder(socket, sockAddrPtr, sockAddrLen);
	if (ftb3) {
		ERROR_LOG(Log::sceNet,
			"[FTB3 WIRE] CONNECT return socket=%d pc=%08x thread=%d result=%d",
			socket, FTB3TracePC(), FTB3TraceThread(), result);
	}
	return result;
}

static inline int sceNetInetSend(int socket, u32 bufPtr, u32 bufLen, u32 flags) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3) {
		const std::string prefix = FTB3TraceHexPrefix(bufPtr, bufLen);
		ERROR_LOG(Log::sceNet,
			"[FTB3 WIRE] SEND enter socket=%d pc=%08x thread=%d len=%u flags=%08x data=%s",
			socket, FTB3TracePC(), FTB3TraceThread(), bufLen, flags, prefix.c_str());
	}
	const int result = sceNetInetSend_PPSSPP_placeholder(socket, bufPtr, bufLen, flags);
	if (ftb3) {
		ERROR_LOG(Log::sceNet,
			"[FTB3 WIRE] SEND return socket=%d pc=%08x thread=%d result=%d",
			socket, FTB3TracePC(), FTB3TraceThread(), result);
	}
	return result;
}

static inline int sceNetInetRecv(int socket, u32 bufPtr, u32 bufLen, u32 flags) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3) {
		ERROR_LOG(Log::sceNet,
			"[FTB3 WIRE] RECV enter socket=%d pc=%08x thread=%d want=%u flags=%08x",
			socket, FTB3TracePC(), FTB3TraceThread(), bufLen, flags);
	}
	const int result = sceNetInetRecv_PPSSPP_placeholder(socket, bufPtr, bufLen, flags);
	if (ftb3) {
		std::string prefix = result > 0 ? FTB3TraceHexPrefix(bufPtr, static_cast<u32>(result)) : "<none>";
		ERROR_LOG(Log::sceNet,
			"[FTB3 WIRE] RECV return socket=%d pc=%08x thread=%d result=%d data=%s",
			socket, FTB3TracePC(), FTB3TraceThread(), result, prefix.c_str());
	}
	return result;
}

static inline int sceNetInetSendmsg(int socket, u32 msghdrPtr, int flags) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] SENDMSG enter socket=%d pc=%08x thread=%d msghdr=%08x flags=%08x", socket, FTB3TracePC(), FTB3TraceThread(), msghdrPtr, flags);
	const int result = sceNetInetSendmsg_PPSSPP_placeholder(socket, msghdrPtr, flags);
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] SENDMSG return socket=%d pc=%08x thread=%d result=%d", socket, FTB3TracePC(), FTB3TraceThread(), result);
	return result;
}

static inline int sceNetInetRecvmsg(int socket, u32 msghdrPtr, int flags) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] RECVMSG enter socket=%d pc=%08x thread=%d msghdr=%08x flags=%08x", socket, FTB3TracePC(), FTB3TraceThread(), msghdrPtr, flags);
	const int result = sceNetInetRecvmsg_PPSSPP_placeholder(socket, msghdrPtr, flags);
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] RECVMSG return socket=%d pc=%08x thread=%d result=%d", socket, FTB3TracePC(), FTB3TraceThread(), result);
	return result;
}

static inline int sceNetInetShutdown(int socket, int how) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] SHUTDOWN socket=%d pc=%08x thread=%d how=%d", socket, FTB3TracePC(), FTB3TraceThread(), how);
	return sceNetInetShutdown_PPSSPP_placeholder(socket, how);
}

static inline int sceNetInetSocketAbort(int socket) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] ABORT socket=%d pc=%08x thread=%d", socket, FTB3TracePC(), FTB3TraceThread());
	const int result = sceNetInetSocketAbort_PPSSPP_placeholder(socket);
	g_ftb3RawTlsSockets.erase(socket);
	return result;
}

static inline int sceNetInetClose(int socket) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] CLOSE socket=%d pc=%08x thread=%d", socket, FTB3TracePC(), FTB3TraceThread());
	const int result = sceNetInetClose_PPSSPP_placeholder(socket);
	g_ftb3RawTlsSockets.erase(socket);
	return result;
}

static inline int sceNetInetCloseWithRST(int socket) {
	const bool ftb3 = g_ftb3RawTlsSockets.count(socket) != 0;
	if (ftb3)
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] CLOSE_RST socket=%d pc=%08x thread=%d", socket, FTB3TracePC(), FTB3TraceThread());
	const int result = sceNetInetCloseWithRST_PPSSPP_placeholder(socket);
	g_ftb3RawTlsSockets.erase(socket);
	return result;
}

static inline int sceNetInetTerm() {
	if (!g_ftb3RawTlsSockets.empty())
		ERROR_LOG(Log::sceNet, "[FTB3 WIRE] INET_TERM pc=%08x thread=%d trackedSockets=%zu", FTB3TracePC(), FTB3TraceThread(), g_ftb3RawTlsSockets.size());
	const int result = sceNetInetTerm_PPSSPP_placeholder();
	g_ftb3RawTlsSockets.clear();
	return result;
}

#define sceNetInetConnect(...) sceNetInetConnect_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetSend(...) sceNetInetSend_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetRecv(...) sceNetInetRecv_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetSendmsg(...) sceNetInetSendmsg_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetRecvmsg(...) sceNetInetRecvmsg_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetShutdown(...) sceNetInetShutdown_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetSocketAbort(...) sceNetInetSocketAbort_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetClose(...) sceNetInetClose_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetCloseWithRST(...) sceNetInetCloseWithRST_PPSSPP_placeholder(__VA_ARGS__)
#define sceNetInetTerm(...) sceNetInetTerm_PPSSPP_placeholder(__VA_ARGS__)

void Register_sceNetInet();

void __NetInetShutdown();

int NetApctl_GetState();

int sceNetApctlConnect(int connIndex);
int sceNetInetPoll(u32 fdsPtr, u32 nfds, int timeout);
int sceNetApctlDisconnect();
