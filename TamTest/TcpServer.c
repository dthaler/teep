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

    /* Send message length. */
    bytesSent = send(g_TcpSessionSocket, (char*)&messageLength, sizeof(messageLength), 0);
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
    char* message = NULL;
    int messageLength = 0;

    /* Accept a client session. */
    while (g_TcpSessionSocket == INVALID_SOCKET) {
        SOCKADDR_STORAGE clientAddress;
        int addrlen = sizeof(clientAddress);
        g_TcpSessionSocket = accept(g_TcpListenSocket, (PSOCKADDR)&clientAddress, &addrlen);
    }

    /* We now have a session.  Send a GetDeviceStateRequest message on it. */
    err = OTrPHandleClientConnect(&message, &messageLength);
    if (err) {
        return err;
    }

    err = SendTcpMessage(message, messageLength);
    return err;
}

int HandleTcpMessage(void)
{
    int bytesReceived;
    int inputMessageLength;
    char* inputMessage;
    int outputMessageLength;
    char* outputMessage;
    int err;

    /* Read message length. */
    bytesReceived = recv(g_TcpSessionSocket, (char*)&inputMessageLength, sizeof(inputMessageLength), MSG_WAITALL);
    if (bytesReceived < sizeof(inputMessageLength)) {
        return FALSE;
    }

    /* Read client message. */
    inputMessage = malloc(inputMessageLength);
    if (inputMessage == NULL) {
        return FALSE;
    }

    bytesReceived = recv(g_TcpSessionSocket, inputMessage, inputMessageLength, MSG_WAITALL);
    if (bytesReceived < inputMessageLength) {
        free(inputMessage);
        return FALSE;
    }

    err = OTrPHandleClientMessage(inputMessage, inputMessageLength, &outputMessage, &outputMessageLength);
    free(inputMessage);
    if (err != 0) {
        return err;
    }

    err = SendTcpMessage(outputMessage, outputMessageLength);
    free(outputMessage);

    return err;
}
