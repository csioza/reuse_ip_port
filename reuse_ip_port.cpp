#include <ctime>
#include <iostream>
#include <ostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <memory.h>
#include <cstdlib>
#include <thread>
#include <sstream>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <poll.h>

//编译命令
//g++ reuse_ip_port.cpp -std=c++11 -lpthread

using namespace std;


std::string ip_ntoa(uint32_t ip) {
    in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

std::string ip_htoa(uint32_t ip) {
    return ip_ntoa(htonl(ip));
}


void SetNonBlock(int fd)
{

}

void SetReUseAddr(int fd)
{
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) 
    {
        std::cout << "Failed to set listen socket option SO_REUSEADDR." << std::endl;
        exit(-1);
    }
}

void SetReUsePort(int fd)
{
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0) 
    {
        std::cout << "Failed to set listen socket option SO_REUSEPORT." << std::endl;
        exit(-1);
    }
}

//获取系统随机分配的端口号, 必须在bind完端口0之后调用
int GetPortBySocketFd(int fd, struct sockaddr_in * svrAddr, socklen_t *socklen) 
{
    getsockname(fd, (struct sockaddr *)svrAddr, socklen);
    int port = ntohs(svrAddr->sin_port);
    std::cout << "Get random port: " << port << std::endl;

    return port;
}

void UdpSend(std::string name, string ip, int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) 
    {
        std::cout << name << "'s udp_fd Failed to create socket." << std::endl;
        exit(-1);
    }

    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_port = htons(port);

    while (1) {
        std:string data = name + "-" + std::to_string(time(NULL));
    
        int ret = sendto(fd, data.c_str(), data.size(), MSG_DONTWAIT, (struct sockaddr*)&addr, addr_len);
        // cout << name << " -> [" << ip << ":" << port << "]" << ", ret:" << ret << ", data: '" << data << "'" << std::endl;

        sleep(3);
    }
}

void UdpRecv(string name, string ip, int port, int reuseaddr, int reuseport)
{
    name += (" [" + ip + ":" + to_string(port) + "]");

    struct sockaddr_in svrAddr;
    svrAddr.sin_family = AF_INET;
    svrAddr.sin_addr.s_addr = inet_addr(ip.c_str());//htonl(INADDR_ANY);
    svrAddr.sin_port = htons(port);

    int listenfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenfd < 0) 
    {
        std::cout << name << "'s udp_fd Failed to create socket." << std::endl;
        exit(-1);
    }

    if (reuseaddr) 
        SetReUseAddr(listenfd);

    if (reuseport) 
        SetReUsePort(listenfd);

    if (bind(listenfd, (struct sockaddr *)&svrAddr, sizeof(svrAddr)) < 0) 
    {
        std::cout << name << "'s udp_fd Failed to bind port, errmsg: " << strerror(errno) << std::endl;
        exit(-1);
    }

    std::cout << name << "'s udp_fd(" << listenfd << ") " << ", reuseaddr:" << reuseaddr << ", reuseport:" << reuseport << std::endl;

    static const int BUF_LEN = 4096;
    unsigned char buf[BUF_LEN] = {0};
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

    struct pollfd pfd;
    pfd.fd = listenfd;
    pfd.events = POLLIN;

    while (1) 
    {
        if (poll(&pfd, 1, 10) <= 0) 
            continue;

        ssize_t len = recvfrom(listenfd, buf, BUF_LEN, MSG_DONTWAIT, (struct sockaddr*) (struct sockaddr *)&clientAddr, &addrLen);

        buf[len] = 0;
        string recv_data = (char *)buf;

        uint32_t ip = ntohl(clientAddr.sin_addr.s_addr);
        uint16_t port = ntohs(clientAddr.sin_port);

        cout << name << " <- " << "[" << ip_ntoa(clientAddr.sin_addr.s_addr) << ":" << port<< "]" 
                << ", len:" << len << ", data: '" << recv_data << "'" << std::endl;
    }
}


void TcpSend(std::string name, string ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);//IPPROTO_TCP
    if (fd < 0) 
    {
        std::cout << name << "'s tcp_fd Failed to create socket." << std::endl;
        exit(-1);
    }

    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_port = htons(port);

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cout << name << "'s tcp_fd connect <" << ip << ":" << to_string(port) <<  "> error."  << std::endl;
        exit(-1);
    }

    while (1) {
        std:string data = name + "-" + std::to_string(time(NULL));
    
        int ret = send(fd, data.c_str(), data.size(), MSG_NOSIGNAL);

        // cout << name << " -> [" << ip << ":" << port << "]" << ", ret:" << ret << ", data: '" << data << "'" << std::endl;

        sleep(3);
    }
}

void TcpRecv(string name, string ip, int port, int reuseaddr, int reuseport)
{
    name += (" [" + ip + ":" + to_string(port) + "]");

    struct sockaddr_in svrAddr;
    svrAddr.sin_family = AF_INET;
    svrAddr.sin_addr.s_addr = inet_addr(ip.c_str());//htonl(INADDR_ANY);
    svrAddr.sin_port = htons(port);

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) 
    {
        std::cout << name << "'s tcp_fd Failed to create socket." << std::endl;
        exit(-1);
    }

    if (reuseaddr) 
        SetReUseAddr(listenfd);

    if (reuseport) 
        SetReUsePort(listenfd);

    if (bind(listenfd, (struct sockaddr *)&svrAddr, sizeof(svrAddr)) < 0) 
    {
        std::cout << name << "'s tcp_fd Failed to bind port, errmsg: " << strerror(errno) << std::endl;
        exit(-1);
    }

    if (listen(listenfd, SOMAXCONN) < 0)
    {
        std::cout << name << "'s tcp_fd Failed to listen port, errmsg: " << strerror(errno) << std::endl;
        exit(-1);
    }

    std::cout << name << "'s tcp_fd(" << listenfd << ") " << ", reuseaddr:" << reuseaddr << ", reuseport:" << reuseport << std::endl;

    static const int BUF_LEN = 1024;

    while (1) 
    {
        // struct pollfd pfda;
        // pfda.fd = listenfd;
        // pfda.events = POLLIN;

        // if (poll(&pfda, 1, 100000) <= 0) 
        // {
        //     sleep(3);
        //     continue;
        // }

        struct sockaddr_in clientAddr;
        socklen_t in_len    = sizeof(struct sockaddr_in);
        int socket_fd       = accept(listenfd, (struct sockaddr *)&clientAddr, &in_len);

        if (socket_fd < 0) {
            cout << name << " accept, listenfd:" << listenfd << ", socket_fd:" << socket_fd <<", errmsg: " << strerror(errno) << std::endl;
            sleep(3);
            continue;
        }

        uint32_t ip = ntohl(clientAddr.sin_addr.s_addr);
        uint16_t port = ntohs(clientAddr.sin_port);

        cout << name << " accept " << "[" << ip_ntoa(ip) << ":" << port<< "]" << ", socket_fd:" << socket_fd << std::endl;

        std::thread t([=]() {
            // struct pollfd pfd;
            // pfd.fd = socket_fd;
            // pfd.events = POLLIN;

            while (1) {

                // if (poll(&pfd, 1, 10) <= 0) 
                //     continue;

                unsigned char mBuff[BUF_LEN] = {0};
                int count = recv(socket_fd, mBuff, BUF_LEN, 0);
                if (count < 0) {
                    sleep(1);
                    continue;
                }

                mBuff[count] = 0;
                string recv_data = (char *)mBuff;

                cout << name << " <- " << "[" << ip_htoa(ip) << ":" << port<< "]" 
                        << ", len:" << count << ", data: '" << mBuff << "'" << std::endl;
            }
        });

        t.detach();
    }

}

int main(int argc, char** argv)
{
    //=====UDP=====
    std::thread UdpServer1(UdpRecv, "UdpServer-1", "0.0.0.0",       12345, !SO_REUSEADDR, SO_REUSEPORT);
    sleep(1);
    std::thread UdpServer2(UdpRecv, "UdpServer-2", "0.0.0.0",       12345, !SO_REUSEADDR, SO_REUSEPORT);
    sleep(1);
    std::thread UdpServer3(UdpRecv, "UdpServer-3", "0.0.0.0",       12345, !SO_REUSEADDR, SO_REUSEPORT);
    sleep(1);

    std::thread UdpClient1(UdpSend, "UdpClient-1", "172.17.0.2",    12345);
    std::thread UdpClient2(UdpSend, "UdpClient-2", "172.17.0.2",    12345);
    std::thread UdpClient3(UdpSend, "UdpClient-3", "172.17.0.2",    12345);

    //=====TCP=====
    std::thread TcpServer1(TcpRecv, "TcpServer-1", "0.0.0.0",       12345, !SO_REUSEADDR, SO_REUSEPORT);
    sleep(1);
    std::thread TcpServer2(TcpRecv, "TcpServer-2", "0.0.0.0",       12345, !SO_REUSEADDR, SO_REUSEPORT);
    sleep(1);
    std::thread TcpServer3(TcpRecv, "TcpServer-3", "0.0.0.0",       12345, !SO_REUSEADDR, SO_REUSEPORT);
    sleep(1);

    std::thread TcpClient1(TcpSend, "TcpClient-1", "172.17.0.2",    12345);
    std::thread TcpClient2(TcpSend, "TcpClient-2", "172.17.0.2",    12345);
    std::thread TcpClient3(TcpSend, "TcpClient-3", "172.17.0.2",    12345);


    sleep(3000);

    return 0;
}