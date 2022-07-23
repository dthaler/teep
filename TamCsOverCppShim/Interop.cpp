#include "Interop.h"
#include <vcclr.h>
using namespace TamCsOverCppShim;
using namespace System;

TeepAgentSession g_AgentSession;

TamSession::TamSession() {}
TamSession::~TamSession() {}

int TamSession::ProcessConnect(System::String^ acceptMediaType)
{
    pin_ptr<const wchar_t> acceptMediaTypeW = PtrToStringChars(acceptMediaType);
    char acceptMediaTypeA[256];
    sprintf_s(acceptMediaTypeA, sizeof(acceptMediaTypeA), "%ls", acceptMediaTypeW);
    return TamProcessConnect(&g_AgentSession, acceptMediaTypeA);

    return 0;
}

ManagedType::ManagedType() {}
ManagedType::~ManagedType() {}

int ManagedType::TamBrokerStart(System::String^ manifestDirectory, bool simulatedTee)
{
#if 0
    pin_ptr<const wchar_t> manifestDirectoryW = PtrToStringChars(manifestDirectory);
    char manifestDirectoryA[256];
    sprintf_s(manifestDirectoryA, sizeof(manifestDirectoryA), "%ls", manifestDirectoryW);
    return StartTamBroker(manifestDirectoryA, (int)simulatedTee);
#else
    return 0;
#endif
}

int ManagedType::TamBrokerProcess(System::String^ tamUri)
{
#if 0
    pin_ptr<const wchar_t> tamUriW = PtrToStringChars(tamUri);
    return TamBrokerProcess(tamUriW);
#else
    return 0;
#endif
}

void ManagedType::TamBrokerStop()
{
    //StopTamBroker();
}

#if 0
// See https://stackoverflow.com/questions/186477/in-c-cli-how-do-i-declare-and-call-a-function-with-an-out-parameter
// for how output args work.
bool ManagedType::ConvertGedcomFile(
    System::String^ input_path,
    System::String^ save_type,
    System::String^ output_filename,
    [Out] System::String^% log_filename)
{
    pin_ptr<const wchar_t> wch = PtrToStringChars(input_path);
    pin_ptr<const wchar_t> savetypeT = PtrToStringChars(save_type);
    pin_ptr<const wchar_t> outputfilenameT = PtrToStringChars(output_filename);
    char savetypeA[256];
    TtoAbuff(savetypeA, sizeof(savetypeA), savetypeT);
    WCHAR basedir[256];
    wcscpy_s(basedir, CCH(basedir), wch);
    WCHAR* p = wcsrchr(basedir, L'/');
    if (p == nullptr) {
        return false;
    }
    *p = 0;

    // Construct the output file input_path.
    WCHAR buff2[256];
    swprintf_s(buff2, CCH(buff2), L"%s\\%s", basedir, outputfilenameT);
    TtoAbuff(g_outputdir, sizeof(g_outputdir), basedir);

    sprintf_s(g_basedir, CCH(g_basedir), "%ls\\wwwroot", basedir);
    if (!init_backend()) {
        return false;
    }

    database_t db = { 0 };
    PCTSTR logfilenameT = nullptr;
    int ok = load_databaseT(&db, nullptr, nullptr, wch, &logfilenameT);
    if (ok) {
        int st = find_savetype_by_filename(savetypeA);
        if (st < 0) {
            ok = false;
        }
        else {
            // Save the database.
            errno_t err = save_databaseT(&db, st, nullptr, nullptr, buff2);
            if (err != 0) {
                ok = false;
            }
        }
        free_database(&db);
    }

    if (logfilenameT) {
        log_filename = gcnew System::String(logfilenameT);
    }

    uninit_backend();
    return ok;
}
#endif

teep_error_code_t TamQueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    return TEEP_ERR_SUCCESS;
}