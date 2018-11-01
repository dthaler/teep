/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../OTrPTransport.h"
#include "../TamLib/OTrPTamLib.h"

SOCKET g_TcpListenSocket = INVALID_SOCKET;
SOCKET g_TcpSessionSocket = INVALID_SOCKET;

int StartTcpServer(void)
{
    int err;
    ADDRINFO* ai;
    WSADATA wsaData;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        return err;
    }

    err = getaddrinfo(NULL, OTRP_TCP_PORT, NULL, &ai);
    if (err != 0) {
        WSACleanup();
        return err;
    }

    g_TcpListenSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (g_TcpListenSocket == INVALID_SOCKET) {
        err = WSAGetLastError();
        freeaddrinfo(ai);
        WSACleanup();
        return err;
    }

    if (bind(g_TcpListenSocket, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        err = WSAGetLastError();
        freeaddrinfo(ai);
        WSACleanup();
        return err;
    }
    freeaddrinfo(ai);

    if (listen(g_TcpListenSocket, 5) == SOCKET_ERROR) {
        err = WSAGetLastError();
        WSACleanup();
    }

    return 0;
}

void StopTcpServer(void)
{
    closesocket(g_TcpListenSocket);
    WSACleanup();
}

int SendTcpMessage(const char* message, int messageLength)
{
    int bytesSent;
    int err = 0;
    int netLength = htonl(messageLength);

    /* Send message length. */
    bytesSent = send(g_TcpSessionSocket, (char*)&netLength, sizeof(netLength), 0);
    if (bytesSent < sizeof(messageLength)) {
        err = WSAGetLastError();
        return err;
    }

    /* Send message. */
    bytesSent = send(g_TcpSessionSocket, message, messageLength, 0);
    if (bytesSent < messageLength) {
        err = WSAGetLastError();
        return err;
    }

    return 0;
}

int AcceptTcpSession(void)
{
    int err;

    /* Accept a client session. */
    while (g_TcpSessionSocket == INVALID_SOCKET) {
        SOCKADDR_STORAGE clientAddress;
        int addrlen = sizeof(clientAddress);
        g_TcpSessionSocket = accept(g_TcpListenSocket, (PSOCKADDR)&clientAddress, &addrlen);
    }

    /* We now have a session.  Send a GetDeviceStateRequest message on it. */
    err = OTrPHandleClientConnect();
    return err;
}

int HandleTcpMessage(void)
{
    int bytesReceived = 0;
    int messageLength = 0;
    char* message = NULL;
    int err = 0;

    /* Read message length. */
    bytesReceived = recv(g_TcpSessionSocket, (char*)&messageLength, sizeof(messageLength), MSG_WAITALL);
    if (bytesReceived < sizeof(messageLength)) {
        return FALSE;
    }
    messageLength = ntohl(messageLength);
    if (messageLength < 1) {
        return FALSE;
    }

    /* Read client message. */
    message = malloc(messageLength);
    if (message == NULL) {
        return FALSE;
    }

    bytesReceived = recv(g_TcpSessionSocket, message, messageLength, MSG_WAITALL);
    if (bytesReceived < messageLength) {
        free(message);
        return FALSE;
    }

    err = OTrPHandleClientMessage(message, messageLength);
    free(message);
    return err;
}

int ocall_SendOTrPMessage(const char* message, int messageLength)
{
    int err;

    err = SendTcpMessage(message, messageLength);
    return err;
}