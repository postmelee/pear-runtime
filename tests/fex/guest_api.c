/* SPDX-License-Identifier: MIT
 * Original Pear x64 fixture: file/time/event APIs and a native-to-guest callback.
 * No CRT, network or proprietary content. The file is confined to the owned
 * synthetic prefix and is deleted when its handle closes.
 */
#include <stdint.h>
#include <stddef.h>
typedef int32_t Status;
typedef void *Handle;
typedef struct { uint16_t length, capacity; uint16_t *buffer; } Unicode;
typedef struct { uint32_t length; Handle root; Unicode *name; uint32_t attributes; void *security, *quality; } Attributes;
typedef struct { uintptr_t status, bytes; } IO;
#define IMPORT __declspec(dllimport)
IMPORT Status NtTerminateProcess(Handle, Status);
IMPORT Status NtQuerySystemTime(int64_t *);
IMPORT Status NtCreateEvent(Handle *, uint32_t, Attributes *, uint32_t, unsigned char);
IMPORT Status NtSetEvent(Handle, int32_t *);
IMPORT Status NtResetEvent(Handle, int32_t *);
IMPORT Status NtWaitForSingleObject(Handle, unsigned char, int64_t *);
IMPORT Status NtClose(Handle);
IMPORT Status NtCreateFile(Handle *, uint32_t, Attributes *, IO *, int64_t *, uint32_t, uint32_t, uint32_t, uint32_t, void *, uint32_t);
IMPORT Status NtWriteFile(Handle, Handle, void *, void *, IO *, const void *, uint32_t, int64_t *, uint32_t *);
IMPORT Status NtReadFile(Handle, Handle, void *, void *, IO *, void *, uint32_t, int64_t *, uint32_t *);
IMPORT Status RtlRunOnceExecuteOnce(void *, uint32_t (*)(void *, void *, void **), void *, void **);
static uint32_t calls;
static uint32_t callback(void *once, void *parameter, void **context) {
    if (!once || parameter != &calls || !context) return 0;
    ++calls;
    *context = (void *)(uintptr_t)0x12340;
    return 1;
}
static Status exercise(void) {
    int64_t now = 0, zero = 0;
    if (NtQuerySystemTime(&now) || now <= 0) return 81;
    Handle event = 0; int32_t previous = -1;
    if (NtCreateEvent(&event, 0x1f0003, 0, 0, 0)) return 82;
    if (NtSetEvent(event, &previous) || previous != 0 || NtWaitForSingleObject(event, 0, &zero)) return 83;
    if (NtResetEvent(event, &previous) || previous != 1 || NtWaitForSingleObject(event, 0, &zero) != 0x102 || NtClose(event)) return 84;
    static uint16_t path[] = u"\\??\\C:\\pear-stage4-probe.tmp";
    Unicode name = {sizeof(path)-2, sizeof(path), path};
    Attributes attributes = {sizeof(attributes), 0, &name, 0x40, 0, 0};
    Handle file = 0; IO io = {0};
    if (NtCreateFile(&file, 0xc0110000, &attributes, &io, 0, 0x80, 0, 0, 0x1060, 0, 0)) return 85;
    static const uint8_t written[] = {6, 7, 42, 0xa5, 0x5a, 1, 2, 3};
    uint8_t read[8] = {0};
    if (NtWriteFile(file, 0, 0, 0, &io, written, sizeof(written), &zero, 0) || io.bytes != sizeof(written)) return 86;
    if (NtReadFile(file, 0, 0, 0, &io, read, sizeof(read), &zero, 0) || io.bytes != sizeof(read)) return 87;
    for (unsigned i = 0; i != sizeof(read); ++i) if (read[i] != written[i]) return 88;
    if (NtClose(file)) return 89;
    uintptr_t once = 0; void *context = 0;
    if (RtlRunOnceExecuteOnce(&once, callback, &calls, &context) || calls != 1 || context != (void *)(uintptr_t)0x12340) return 90;
    context = 0;
    if (RtlRunOnceExecuteOnce(&once, callback, &calls, &context) || calls != 1 || context != (void *)(uintptr_t)0x12340) return 91;
    return read[0] * read[1];
}
void pear_first_dispatch(void) {
    NtTerminateProcess((Handle)(intptr_t)-1, exercise());
    for (;;) {}
}
