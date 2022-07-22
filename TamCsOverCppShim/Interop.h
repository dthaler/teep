#pragma once

#include <string>
#include "windows.h"
#include "../protocol/TeepTamBrokerLib/TeepTamBrokerLib.h"

using namespace System::Runtime::InteropServices;

namespace TamCsOverCppShim {

    public ref class ManagedType
    {
#if 0
    private:
        database_t* db;
#endif

    public:
        ManagedType();
        ~ManagedType();

        static int TamBrokerStart(System::String^ manifestDirectory, bool simulatedTee);

        static int TamBrokerProcess(System::String^ tamUri);

        static void TamBrokerStop();

#if 0
        bool ConvertGedcomFile(
            System::String^ input_path,
            System::String^ save_type,
            System::String^ output_filename,
            [Out] System::String^% log_filename);
#endif
    };
}