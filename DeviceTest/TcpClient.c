/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <WinSock2.h>
#include <ws2tcpip.h>
#include "TcpClient.h"
#include "..\DeviceLib\OTrPDeviceLib.h"
#include "../OTrPTransport.h"

SOCKET g_TcpSessionSocket = INVALID_SOCKET;

int ConnectToTcpServer(const char* serverName)
{
    ADDRINFO* ai;
    int err;
    WSADATA wsaData;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        return err;
    }

    err = getaddrinfo(serverName, OTRP_TCP_PORT, NULL, &ai);
    if (err != 0) {
        WSACleanup();
        return err;
    }

    g_TcpSessionSocket = socket(ai->ai_family, SOCK_STREAM, 0);
    if (g_TcpSessionSocket == INVALID_SOCKET) {
        err = WSAGetLastError();
        freeaddrinfo(ai);
        WSACleanup();
        return err;
    }

    if (connect(g_TcpSessionSocket, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        err = WSAGetLastError();
        closesocket(g_TcpSessionSocket);
        freeaddrinfo(ai);
        WSACleanup();
        return err;
    }

    freeaddrinfo(ai);
    return 0;
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

int HandleTcpMessage(void)
{
    int bytesReceived;
    int messageLength;
    char* message;
    int err;

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

    err = OTrPHandleDeviceMessage(message, messageLength);

    free(message);

    return (err == 0);
}

void DisconnectFromTcpServer(void)
{
    closesocket(g_TcpSessionSocket);
    WSACleanup();
}

int ocall_SendOTrPMessage(const char* message, int messageLength)
{
    int err;

    err = SendTcpMessage(message, messageLength);
    return err;
}
