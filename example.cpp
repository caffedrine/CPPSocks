#include <iostream>
#include "CSocks.h"

using namespace std;

int main()
{
    try
    {
        CSocks sock("xx.xx.xx.xx", 1080, 4);
        sock.setDestination("checkip.dyndns.com", 80);

        SOCKET hSock = sock.Connect();

        if(hSock == INVALID_SOCKET)
        {
            cout << "ERROR: " << sock.getLastError();
            return -1;
        }

        std::string headers = "GET http://checkip.dyndns.com/ HTTP/1.0\r\n\r\n";

        //Send our request
        cout << endl << "Sending custom request...";
        if(sock.sendData(hSock, headers.c_str(), headers.length()) < 0)
        {
            cout << "failed";
            return -1;
        }
        cout << "done!" << endl;

        std::string fullResp = "";
        char buffer[512];

        cout << "Reading response from server...";
        while(true)
        {
            int retval = recv(hSock, buffer, 512, 0);
            if(retval == 0)
            {
                break;
            }
            else if(retval == SOCKET_ERROR)
            {
                cout << "failed";
                return -1;
            }
            else
            {
                buffer[retval] = 0;
                fullResp +=  buffer;
            }
        }
        cout << "done" << endl;
        cout << "What we have got:" << endl << fullResp;

        closesocket(hSock);
        shutdown(hSock, 2);
    }
    catch(std::exception &e)
    {
        cout << "ERROR: " << e.what() << endl;
        return -1;
    }
    return 0;
}
