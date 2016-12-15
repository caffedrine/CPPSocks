#include <winsock2.h>
#include <string>
#include <iostream>
#include <vector>

class CSocks
{
    typedef enum
    {
        SOCKS4 = 4,
        SOCKS5 = 5,
    }SockVersion;

    typedef struct
    {
        SockVersion version  = SOCKS4;
        std::string IPAddr   = "";
        std::string hostname = "";
        u_short port         = 1080;
    }SocksInfo;

    typedef struct
    {
        std::string IPAddr   = "";
        std::string hostname = "";
        u_short port         = 80;
    }DestInfo;

public:
    //Constructors/Destructors
    CSocks(std::string socketIPorHost, u_short socketPort, int version);
    ~CSocks();

    //Our methods
    SOCKET Connect();
    int sendData(SOCKET s, const void *buffer, int buflen);
    int recvData(SOCKET s, void *buffer, int buflen);

    //Sets
    void setDestination(std::string destIPorHostname, u_short destPort);

    //Gets
    std::string getLastError();

private:
    //Variables
    SocksInfo socksInfo;
    DestInfo destInfo;
    std::string lastError = "";

    //Main methods
    SOCKET connectSOCKS4(SOCKET hSocksSocket);
    SOCKET connectSOCKS5(SOCKET hSocksSocket);

    //Gets, sets and all the stuff
    void setLastError(std::string err);

    //Util functions
    std::string resolveHostname(std::string hostname);
    bool isValidIPv4(std::string ip);
    bool isValidHostname(std::string hostname);
};