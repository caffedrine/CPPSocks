//////////////////////////////////////////////////////////////////
//    ____ ____             _            ____ _                 //
//   / ___/ ___|  ___   ___| | _____    / ___| | __ _ ___ ___   //
//  | |   \___ \ / _ \ / __| |/ / __|  | |   | |/ _` / __/ __|  //
//  | |___ ___) | (_) | (__|   <\__ \  | |___| | (_| \__ \__ \  //
//   \____|____/ \___/ \___|_|\_\___/   \____|_|\__,_|___/___/  //
//////////////////////////////////////////////////////////////////
#include "CSocks.h"

//Starting with constructors
CSocks::CSocks(std::string socketIPorHost, u_short socksPort, int version)
{
    //Check for correct winsock version!
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,0), &wsaData)==0)
    {
        if (LOBYTE(wsaData.wVersion) < 2)
            throw std::logic_error("Minimimum required WinSock32 version can't be loaded!");
    }
    else
    {
        throw std::logic_error("WSA Startup Failed!");
    }

    //If everything is OK, we can setup variables and check
    if( version != 4 && version != 5)
    {
        setLastError("Incorrect SOCKS Version!");
        throw std::logic_error("Incorrect SOCKS Version!");
    }
    else
    {
        socksInfo.version = (SockVersion)version;
    }

    //Checking if port is valid
    if(socksPort <= 0 || socksPort > 65535)
    {
        setLastError("Invalid SOCKS port!");
        throw std::logic_error("Invalid SOCKS port!");
    }
    else
    {
        socksInfo.port = socksPort;
    }

    //If we gonna use SOCKS4, the destination should be resolved locally.
    if(isValidIPv4(socketIPorHost))
    {
        socksInfo.hostname = socketIPorHost;
        socksInfo.IPAddr   = socketIPorHost;
    }
    else
    {
        if(isValidHostname(socketIPorHost))
        {
            socksInfo.hostname = socketIPorHost;
            socksInfo.IPAddr   = resolveHostname( socketIPorHost );
        }
        else
        {
            setLastError("Invalid SOCKS IP/Hostname!");
            throw std::logic_error("Invalid SOCKS IP/Hostname!");
        }
    }
}

CSocks::~CSocks()
{
    if(WSACleanup() != 0)
        throw std::logic_error("Windows Socket Cleanup failed!");
}

//   ____        _     _ _
//  |  _ \ _   _| |__ | (_) ___ ___
//  | |_) | | | | '_ \| | |/ __/ __|
//  |  __/| |_| | |_) | | | (__\__ \
//  |_|    \__,_|_.__/|_|_|\___|___/
SOCKET CSocks::Connect()
{
    //Init sockaddr for SOCKS5
    sockaddr_in socks;
    socks.sin_family = AF_INET;                                      // host byte order
    socks.sin_port = htons(socksInfo.port);                          // short, network byte order
    socks.sin_addr.S_un.S_addr = inet_addr(socksInfo.IPAddr.c_str());// adding socks server IP address into structure

    //Creating socket handler
    SOCKET hSocketSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hSocketSock == INVALID_SOCKET)
    {
        setLastError("Failed to create SOCKET handler! Desc: " + WSAGetLastError());
        return INVALID_SOCKET;
    }

    //Time to connect to SOCKS server
    if (connect(hSocketSock, reinterpret_cast<sockaddr *>(&socks), sizeof(socks)) != 0)
    {
        setLastError("Failed to connect to SOCKS server!");
        closesocket(hSocketSock);
        return INVALID_SOCKET;
    }

    //The way splits here
    if(socksInfo.version == SOCKS4)
    {
        return connectSOCKS4(hSocketSock);
    }
    else
    {
        return connectSOCKS5(hSocketSock);
    }
}

//Sets and Gets
void CSocks::setDestination(std::string destIPorHostname, u_short destPort)
{
    if(isValidIPv4(destIPorHostname))
    {
        destInfo.hostname = destIPorHostname;
        destInfo.IPAddr   = destIPorHostname;
    }
    else
    {
        if(isValidHostname(destIPorHostname))
        {
            destInfo.hostname = destIPorHostname;
            destInfo.IPAddr = (socksInfo.version == SOCKS4) ? resolveHostname( destIPorHostname ) : destIPorHostname; //resolve only for SOCKS4
        }
        else
        {
            setLastError("Invalid destination IP/Hostname!");
            throw std::logic_error("Invalid destination IP/Hostname!");
        }
    }

    if(destPort <= 0 || destPort > 65535)
    {
        setLastError("Invalid destination port!");
        throw std::logic_error("Invalid destination port!");
    }
    else
    {
        destInfo.port = destPort;
    }
}

std::string CSocks::getLastError()
{
    return CSocks::lastError;
}
//   ____       _            _
//  |  _ \ _ __(_)_   ____ _| |_ ___  ___
//  | |_) | '__| \ \ / / _` | __/ _ \/ __|
//  |  __/| |  | |\ V / (_| | ||  __/\__ \
//  |_|   |_|  |_| \_/ \__,_|\__\___||___/
SOCKET CSocks::connectSOCKS4(SOCKET hSocksSocket)
{
    //Convert dest info in correct format
    u_short destPort = htons(destInfo.port);
    unsigned long destIp = inet_addr( destInfo.IPAddr.c_str() );

    //Documentation: http://www.openssh.com/txt/socks4.protocol

    //The packet we have to build
    //         +----+----+----+----+----+----+----+----+----+----+....+----+
    //         | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
    //         +----+----+----+----+----+----+----+----+----+----+....+----+
    //# of bytes: 1    1      2              4           variable       1

    //This packet is meant to inform socks server who's the destination we want to communicate with.

    int initPacketLen = 9;
    char *initPacket = new char[initPacketLen]; //9 because we don't use auth.

    initPacket[0] = 4;                      //Sock version we use is 4
    initPacket[1] = 1;                      //Connect code
    memcpy(initPacket + 2, &destPort, 2);   //Copy port into
    memcpy(initPacket + 4, &destIp, 4);     //Copy ip address
    initPacket[8] = 0;                      //No username for auth provided

    //Sending our packet!
    if(sendData(hSocksSocket, initPacket, initPacketLen) < 0)
    {
        setLastError("Failed to send INIT packet!");
        return INVALID_SOCKET;
    }

    //Don't need init packet anymore as we have send it.
    delete[] initPacket;

    //We want a replay. This will tell us if the sock is able to communicate with destination

    int replyLen = 8; //WHY 8? Because of table below :)
    char replay[replyLen];
    memset(&replay, 0, (size_t)replyLen);

    //Reading the response
    if(recvData(hSocksSocket, replay, replyLen) <= 0)
    {
        setLastError("Error while reading socks response!");
        return INVALID_SOCKET;
    }

    //         Expected response format:
    //         +----+----+----+----+----+----+----+----+
    //         | VN | CD | DSTPORT |      DSTIP        |
    //         +----+----+----+----+----+----+----+----+
    //# of bytes: 1    1      2              4
    //    VN is the version of the reply code and should be 0. CD is the result
    //    code with one of the following values:
    //
    //    90: request granted
    //    91: request rejected or failed
    //    92: request rejected becasue SOCKS server cannot connect to identd on the client
    //    93: request rejected because the client program and identd report different user-ids.

    //So, we have to check if replay is ok :)
    if(replay[0] != 0)
    {
        setLastError("Invalid SOCKS version returned by server!");
        return INVALID_SOCKET;
    }

    //Returned code: 90 = access granted
    if(replay[1] != 90)
    {
        setLastError("Request Not granted in returned code!" );
        return INVALID_SOCKET;
    }

    return hSocksSocket;

    //Don't forget about:
    //closesocket(hSocketSock);
    //shutdown(hSocketSock, 2);
}

SOCKET CSocks::connectSOCKS5(SOCKET hSocketSock)
{
    //Documentation: https://tools.ietf.org/html/rfc1928

    //We have to send first packet which tell to SOCKS5 to enter on
    //sub-negociation mode so we can connect to actual destination server

    //    The client connects to the server, and sends a version
    //    identifier/method selection message:
    //    +----+----------+----------+
    //    |VER | NMETHODS | METHODS  |
    //    +----+----------+----------+
    //    | 1  |    1     | 1 to 255 |
    //    +----+----------+----------+

    //Allocate space for the first initialize packet and his replay
    int initPacket1Length = 3;
    char initPacket1[initPacket1Length];
    initPacket1[0] = 5;  //SOCKS Version. [VER]
    initPacket1[1] = 1;  //No. of methods [NMETHODS]
    initPacket1[2] = 0;  //No auth required [X’00’]

    //Now we are sending the packet we just created
    if (sendData(hSocketSock, initPacket1, initPacket1Length) < 0)
    {
        setLastError("Can't send first init packet to SOCKS server!");
        closesocket(hSocketSock);
        return INVALID_SOCKET;
    }

    //And our expected replay format:
    //
    //    The server selects from one of the methods given in METHODS, and
    //    sends a METHOD selection message:
    //    +----+--------+
    //    |VER | METHOD |
    //    +----+--------+
    //    | 1  |   1    |
    //    +----+--------+

    //Receiving response from server
    char reply1[2];
    if (recvData(hSocketSock, reply1, 2) <= 0)
    {
        setLastError("Error reading first init packet response!");
        closesocket(hSocketSock);
        return INVALID_SOCKET;
    }

    //reply[0] = our version
    //reply[1] = out method. [X’00’ NO AUTHENTICATION REQUIRED]
    if( !(reply1[0] == 5 && reply1[1] == 0) )
    {
        setLastError("Bad response for init packet!");
        closesocket(hSocketSock);
        return INVALID_SOCKET;
    }

    //We have to build initialize packet. This will transmit to SOCKS5 server
    //the web server we want to connect to.
    //
    //    The SOCKS request is formed as follows:
    //
    //    +----+-----+-------+------+----------+----------+
    //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X’00’ |   1  | Variable |    2     |
    //    +----+-----+-------+------+----------+----------+
    //
    //    Where:
    //    o VER protocol version: X’05’
    //    o CMD
    //    o CONNECT X’01’
    //    o BIND X’02’
    //    o UDP ASSOCIATE X’03’
    //    o RSV RESERVED
    //    o ATYP address type of following address
    //    o IP V4 address: X’01’
    //    o DOMAINNAME: X’03’
    //    o IP V6 address: X’04’
    //    o DST.ADDR desired destination address
    //    o DST.PORT desired destination port in network octet
    //    order

    int hostlen = std::max((int)destInfo.hostname.size(), 255);

    //Building that packet
    char *initPacket2 = new char[7+hostlen];
    initPacket2[0] = 5; //SOCKS Version;
    initPacket2[1] = 1; //1 = CONNECT, 2 = BIND, 3 = UDP ASSOCIATE;
    initPacket2[2] = 0; //Reserved byte
    initPacket2[3] = 3; //1 = IPv4, 3 = DOMAINNAME, 4 = IPv6
    initPacket2[4] = (char) hostlen;
    memcpy(&initPacket2[5], destInfo.hostname.c_str(), hostlen);
    *((u_short*) &(initPacket2[5+hostlen])) = htons(destInfo.port);

    //Send the second init packet to server. This will inform the SOCKS5 server
    //what is our target.
    if (sendData(hSocketSock, initPacket2, 7+hostlen) < 0)
    {
        setLastError("Can't send second init packet!");
        delete[] initPacket2;
        closesocket(hSocketSock);
        return INVALID_SOCKET;
    }
    delete[] initPacket2;

    //Reading the response
    //Expected response format:

    //    The SOCKS request information is sent by the client as soon as it has
    //    established a connection to the SOCKS server, and completed the
    //    authentication negotiations. The server evaluates the request, and
    //    returns a reply formed as follows:

    //    +----+-----+-------+------+----------+----------+
    //    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X’00’ |  1   | Variable |   2      |
    //    +----+-----+-------+------+----------+----------+
    //                              Where:
    //    o VER protocol version: X’05’
    //    o REP Reply field:
    //        o X’00’ succeeded
    //        o X’01’ general SOCKS server failure
    //        o X’02’ connection not allowed by ruleset
    //        o X’03’ Network unreachable
    //        o X’04’ Host unreachable
    //        o X’05’ Connection refused
    //        o X’06’ TTL expired
    //        o X’07’ Command not supported
    //        o X’08’ Address type not supported
    //        o X’09’ to X’FF’ unassigned
    //    ......................................

    //Reading response for second packed we have sent
    char reply2[262];
    if (recvData(hSocketSock, reply2, 4) <= 0)
    {
        setLastError("Error while reading response for second init packet!");
        closesocket(hSocketSock);
        return INVALID_SOCKET;
    }

    if (!(reply2[0] == 5 && reply2[1] == 0))
    {
        setLastError("The connection between and SOCKS and DESTINATION can't be established!");
        closesocket(hSocketSock);
        return INVALID_SOCKET;
    }

    //Huh, if we are here, then everything is perfect!
    //Let's return the handler!
    return hSocketSock;

    //Don't forget about:
    //closesocket(hSocketSock);
    //shutdown(hSocketSock, 2);
}

int CSocks::sendData(SOCKET s, const void *buffer, int buflen)
{
    const char *pbuf = (const char*) buffer;
    while (buflen > 0)
    {
        int numSent = send(s, pbuf, buflen, 0);
        if (numSent == SOCKET_ERROR)
            return SOCKET_ERROR;
        pbuf += numSent;
        buflen -= numSent;
    }
    return 1;
}

int CSocks::recvData(SOCKET s, void *buffer, int buflen)
{
    char *pbuf = (char*) buffer;
    while (buflen > 0)
    {
        int numRecv = recv(s, pbuf, buflen, 0);
        if (numRecv == SOCKET_ERROR)
            return SOCKET_ERROR;
        if (numRecv == 0)
            return 0;
        pbuf += numRecv;
        buflen -= numRecv;
    }
    return 1;
}

void CSocks::setLastError(std::string err)
{
    CSocks::lastError = err;
}

std::string CSocks::resolveHostname(std::string hostname)
{
    hostent *record = gethostbyname(hostname.c_str());
    if(record == NULL)
        return "";

    in_addr *address = (in_addr *)record->h_addr;
    return inet_ntoa( *address );
}

bool CSocks::isValidIPv4(std::string ip)
{
    const std::string address = ip;

    std::vector<std::string> arr;
    int k = 0;
    arr.push_back(std::string());
    for (std::string::const_iterator i = address.begin(); i != address.end(); ++i)
    {
        if (*i == '.')
        {
            ++k;
            arr.push_back(std::string());
            if (k == 4)
            {
                return false;
            }
            continue;
        }
        if (*i >= '0' && *i <= '9')
        {
            arr[k] += *i;
        }
        else
        {
            return false;
        }
        if (arr[k].size() > 3)
        {
            return false;
        }
    }

    if (k != 3)
    {
        return false;
    }
    for (int i = 0; i != 4; ++i)
    {
        const char* nPtr = arr[i].c_str();
        char* endPtr = 0;
        const unsigned long a = ::strtoul(nPtr, &endPtr, 10);
        if (nPtr == endPtr)
        {
            return false;
        }
        if (a > 255)
        {
            return false;
        }
    }
    return true;
}

bool CSocks::isValidHostname(std::string hostname)
{
    if( resolveHostname(hostname) != "")
        return true;
    return false;
}