#pragma once
extern "C" {
#include <ntddk.h>
}


////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//


////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//


////////////////////////////////////////////////////////////////////////////////
//
// types
//


////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C
NTSTATUS RootkitEnableRootkit(
    __in ULONG_PTR ReturnAddressOffset,
    __in ULONG_PTR AsmHandler,
    __in ULONG_PTR AsmHandlerEnd);


////////////////////////////////////////////////////////////////////////////////
//
// variables
//


////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

