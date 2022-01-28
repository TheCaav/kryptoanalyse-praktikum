#include <sys/types.h>

#define NETNAME_LEN 80
typedef char NetName[NETNAME_LEN]; 

typedef struct {
  int fd;
  NetName peer;
} ConnStr;

typedef ConnStr *Connection;

typedef int PortConnection;

PortConnection OpenPort(const char *name);

/*
 * Accepts a Connection. This method forks.
 * It returns (in a new process) for each accepted connection.
 * The parent process never returns.
 */
Connection WaitAtPort(PortConnection p);
Connection WaitAtPort_inc(PortConnection p, void (*inc)(void));

char *PeerName(Connection c);
void DisConnect(Connection con);
const char* NET_ErrorText(void);
int Receive (Connection con, void *data, size_t len);
void ReceiveAll (Connection con, void *data, size_t len);
void Transmit (Connection con, const void *data, size_t len);
char *MakeNetName(const char *name);
Connection ConnectTo(const NetName name, const char *target);
int sock_timeout(Connection c, int timeout);
