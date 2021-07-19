// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#ifdef USE_TCP
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../TeepTransport.h"
#include "../TamLib/TeepTamLib.h"

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
    err = TeepHandleConnect();
    return err;
}

void CloseTcpSession(void)
{
    closesocket(g_TcpSessionSocket);
    g_TcpSessionSocket = INVALID_SOCKET;
}

/* Returns 0 on success, non-zero on failure. */
int HandleTcpMessage(void)
{
    int bytesReceived = 0;
    int messageLength = 0;
    char* message = NULL;
    int err = 0;

    /* Read message length. */
    bytesReceived = recv(g_TcpSessionSocket, (char*)&messageLength, sizeof(messageLength), MSG_WAITALL);
    if (bytesReceived < sizeof(messageLength)) {
        return TRUE;
    }
    messageLength = ntohl(messageLength);
    if (messageLength < 1) {
        return TRUE;
    }

    /* Read client message. */
    message = malloc(messageLength);
    if (message == NULL) {
        return TRUE;
    }

    bytesReceived = recv(g_TcpSessionSocket, message, messageLength, MSG_WAITALL);
    if (bytesReceived < messageLength) {
        free(message);
        return TRUE;
    }

    err = TeepHandleMessage(message, messageLength);
    free(message);
    return err;
}

int ocall_SendTeepMessage(const char* message)
{
    int err;

    err = SendTcpMessage(message, strlen(message));
    return err;
}
#endif
