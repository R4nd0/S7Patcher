// Exercise the actual patch writer/validator against owned synthetic memory.
// No game file is loaded and no native game function is ever called.
#include "offline_bootstrap.cpp"
#include <cstdio>
void ReportLocalStatus(const char*) { SetLastError(12345); }
namespace {
#ifdef S7_LOCAL_PAIR_LAB
uintptr_t lab_join_arguments[6]{};
int lab_join_code = 1;
const char* lab_rejection_literal = nullptr;
void* lab_dispatch_arguments[3]{};
void* lab_echo_self = nullptr;
unsigned int lab_echo_phase = 0;
int lab_echo_timeout = 0;
unsigned int lab_reason_length = 0;
unsigned char* pump_scheduler = nullptr;
unsigned int pending_core_tasks = 0;
uintptr_t lab_ticket_words[8]{};
uintptr_t lab_ticket_return = 0;
uintptr_t __fastcall FakeTicketWords(void* self, void*, uintptr_t a, uintptr_t b, uintptr_t c,
    uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    const uintptr_t words[] = {reinterpret_cast<uintptr_t>(self), a, b, c, d, e, f, g};
    memcpy(lab_ticket_words, words, sizeof(words)); SetLastError(6789); return lab_ticket_return;
}
NativeResult* __fastcall FakeTicketResultWords(void* self, void*, NativeResult* result, uintptr_t b, uintptr_t c,
    uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    FakeTicketWords(self, nullptr, reinterpret_cast<uintptr_t>(result), b, c, d, e, f, g);
    result->code = lab_join_code; result->detail = 123; return result;
}
void* __fastcall FakeTicketLookup(void* self, void*, uintptr_t reference) {
    lab_ticket_words[0]=reinterpret_cast<uintptr_t>(self); lab_ticket_words[1]=reference;
    SetLastError(6789); return reinterpret_cast<void*>(lab_ticket_return);
}
void __fastcall FakeHostJoinGate(void* self, void*, void* event) {
    lab_dispatch_arguments[0]=self; lab_dispatch_arguments[1]=event; SetLastError(6789);
}
NativeResult* __fastcall FakeHostEventRoute(void* self, void*, NativeResult* result,
    uintptr_t context, void* event, uintptr_t destination) {
    lab_ticket_words[0]=reinterpret_cast<uintptr_t>(self);
    lab_ticket_words[1]=context; lab_ticket_words[2]=reinterpret_cast<uintptr_t>(event);
    lab_ticket_words[3]=destination;
    result->code=lab_join_code; result->detail=123; SetLastError(6789); return result;
}
bool __fastcall FakeHostEventType(void* event, void*, uintptr_t left, uintptr_t right) {
    lab_ticket_words[0]=reinterpret_cast<uintptr_t>(event);
    lab_ticket_words[1]=left; lab_ticket_words[2]=right;
    SetLastError(6789); return lab_join_code == 1;
}
void* __fastcall FakePlayerReason(void* output, void*, const char* text, unsigned int length) {
    lab_rejection_literal = text; lab_reason_length = length; SetLastError(6789); return output;
}
NativeResult* __fastcall FakeEchoDispatcher(void* self, void*, NativeResult* result, unsigned int phase, int timeout) {
    lab_echo_self = self; lab_echo_phase = phase; lab_echo_timeout = timeout;
    result->code = 2; result->detail = 654; SetLastError(6789); return result;
}
NativeResult* __fastcall FakeSessionDispatch(void* self, void*, NativeResult* result, void* event) {
    lab_dispatch_arguments[0] = self; lab_dispatch_arguments[1] = result; lab_dispatch_arguments[2] = event;
    result->code = lab_join_code; result->detail = 987; SetLastError(6789); return result;
}
void* __fastcall FakeLabDiagnosticCtor(void* output, void*, const char* text) {
    lab_rejection_literal = text; SetLastError(6789); return output;
}
NativeResult* __stdcall FakeLabJoinRequest(NativeResult* result, void* peer, void* session,
    void* metadata, void* job, void* callback, unsigned int flags) {
    lab_join_arguments[0] = reinterpret_cast<uintptr_t>(peer);
    lab_join_arguments[1] = reinterpret_cast<uintptr_t>(session);
    lab_join_arguments[2] = reinterpret_cast<uintptr_t>(metadata);
    lab_join_arguments[3] = reinterpret_cast<uintptr_t>(job);
    lab_join_arguments[4] = reinterpret_cast<uintptr_t>(callback);
    lab_join_arguments[5] = flags;
    result->code = lab_join_code; result->detail = 123;
    SetLastError(6789);
    return result;
}
#endif
std::vector<char> pump_trace;
unsigned char* pump_network = nullptr;
unsigned char* pump_owner = nullptr;
int pump_mode = 0;
#ifdef S7_LOCAL_PAIR_LAB
NativeResult* __fastcall FakeCoreBoundary(void*, void*, NativeResult* result, unsigned int phase) {
    pump_trace.push_back(phase == 1 ? 'P' : phase == 2 ? 'Q' : '!');
    PumpOfflineBootstrap();
    if (pump_mode == 16 && phase == 1) *Native<unsigned char**>(0x1379E14) = nullptr;
    if (pump_mode == 17 && phase == 2) *reinterpret_cast<void**>(pump_network + 0x2c) = nullptr;
    if (pump_mode == 18 && phase == 1) pump_network[0x30] = 0;
    result->code = 1; result->detail = 0; return result;
}
NativeResult* __cdecl FakeEchoUpdate(NativeResult* result, unsigned int phase, int timeout) {
    pump_trace.push_back(phase == 3 && timeout == -1 ? 'E' : '!');
    if (pump_active) PumpOfflineBootstrap();
    if (pump_mode == 13) *Native<unsigned char**>(0x1379E14) = nullptr;
    if (pump_mode == 14) *reinterpret_cast<void**>(pump_network + 0x2c) = nullptr;
    result->code = 2; result->detail = 78; return result;
}
void __fastcall FakeManagerUpdate(void*, void*) {
    pump_trace.push_back('J');
    PumpOfflineBootstrap();
    if (pump_mode == 11) *Native<unsigned char**>(0x1379E14) = nullptr;
    if (pump_mode == 12) *reinterpret_cast<void**>(pump_owner + 0x100) = pump_owner;
}
void TickFakeManager() {
    UpdateLabManager(*reinterpret_cast<void**>(pump_owner + 0x100), nullptr);
}
#endif
int network_getter_calls = 0;
int search_space_calls = 0;
int search_space_mode = 0;
char search_space_copy[129]{};
void __fastcall FakeSetSearchSpace(void* self, void*, const NativeSmallString* input) {
    ++search_space_calls;
    auto* output = reinterpret_cast<NativeSmallString*>(static_cast<unsigned char*>(self) + 0x10);
    *output = *input;
    if (input->capacity >= 16) {
        memcpy(search_space_copy, SmallStringData(*input), input->length + 1);
        const char* copy = search_space_copy;
        memcpy(output->inline_data, &copy, sizeof(copy));
    }
    if (search_space_mode == 1) *Native<void**>(0x1379E14) = nullptr;
    if (search_space_mode == 2) output->inline_data[0] = '?';
}
void* __cdecl FakeNetworkGetter() { ++network_getter_calls; return pump_network; }
void __fastcall FakeOwnerUpdate(void*, void*) {
    pump_trace.push_back('O');
    if (pump_mode == 8) *Native<unsigned char**>(0x1379E14) = nullptr;
}
void __fastcall FakeMasterUpdate(void*, void*) {
    pump_trace.push_back('M');
    PumpOfflineBootstrap(); // Recursive bridge entry must be ignored.
    if (pump_mode == 2) *Native<unsigned char**>(0x1379E14) = nullptr;
    if (pump_mode == 3) *reinterpret_cast<void**>(pump_network + 0xa18) = nullptr;
    if (pump_mode == 4) *reinterpret_cast<void**>(pump_network + 0x2c) = nullptr;
#ifdef S7_LOCAL_PAIR_LAB
    if (pump_mode == 9) TickFakeManager();
    if (pump_mode == 15) { NativeResult result{}; UpdateLabEcho(&result, 3, -1); }
#endif
}
NativeResult* __fastcall FakeCoreUpdate(void*, void*, NativeResult* result, unsigned int phase) {
    pump_trace.push_back(phase == 3 ? 'C' : '!');
#ifdef S7_LOCAL_PAIR_LAB
    if (pump_scheduler) ++*reinterpret_cast<unsigned int*>(pump_scheduler + 0x78);
    pending_core_tasks = 0;
#endif
    if (pump_mode == 1 || pump_mode == 8) UpdateLocalGame(pump_owner, nullptr);
    if (pump_mode == 5) *Native<unsigned char**>(0x1379E14) = nullptr;
    if (pump_mode == 6) *reinterpret_cast<void**>(pump_network + 0xa18) = nullptr;
    if (pump_mode == 7) *reinterpret_cast<void**>(pump_network + 0x2c) = nullptr;
#ifdef S7_LOCAL_PAIR_LAB
    if (pump_mode == 10) TickFakeManager();
#endif
    result->code = 1; result->detail = 0;
    return result;
}
bool FakeJump(uintptr_t address, const void* target) {
    auto* bytes = Native<unsigned char*>(address);
    DWORD old = 0;
    if (!VirtualProtect(bytes, 5, PAGE_EXECUTE_READWRITE, &old)) return false;
    bytes[0] = 0xe9;
    uint32_t relative = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(target)) -
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bytes) + 5);
    memcpy(bytes + 1, &relative, 4);
    return FlushInstructionCache(GetCurrentProcess(), bytes, 5) != FALSE;
}
}
int main() {
    int failures = 0, checks = 0;
    auto check = [&](bool result) { ++checks; if (!result) { ++failures; std::printf("Failed check %d\n", checks); } };
    const char* lab_digests[] = {
        "722cb6e616851f20fae90b29c8af65df8aa94f353b0739e44c24721cfb574e13",
        "78c7a4b87e2f8dceb95eaaac9ab8cdd559ce482fc800129345e952b711974a8a"};
    unsigned char digest[32]{};
    check(!AcceptExecutableDigest(digest));
#ifdef S7_LOCAL_PAIR_LAB
    check(!AcceptExecutableDigest(ExpectedHash));
#else
    check(AcceptExecutableDigest(ExpectedHash));
#endif
    for (int slot = 0; slot < 2; ++slot) {
        for (int i = 0; i < 32; ++i) {
            char hex[3] = { lab_digests[slot][i*2], lab_digests[slot][i*2+1], 0 };
            digest[i] = static_cast<unsigned char>(strtoul(hex, nullptr, 16));
        }
#ifdef S7_LOCAL_PAIR_LAB
        check(AcceptExecutableDigest(digest));
        check(local_pair_bind.load() == 0x7f000002u + slot);
#else
        check(!AcceptExecutableDigest(digest));
#endif
        for (int i = 0; i < 32; ++i) {
            digest[i] ^= 1; check(!AcceptExecutableDigest(digest)); digest[i] ^= 1;
        }
    }
    auto* memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, ExpectedImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory) return 2;
    image_base = reinterpret_cast<uintptr_t>(memory);
#ifdef S7_LOCAL_PAIR_LAB
    check(FakeJump(0xD49B10, reinterpret_cast<const void*>(&FakeLabJoinRequest)));
    check(FakeJump(0xC33020, reinterpret_cast<const void*>(&FakeEchoDispatcher)));
    {
        unsigned char dispatcher[4]{}; NativeResult result{};
        check(ObserveLabEchoDispatcher(dispatcher, nullptr, &result, 3, -1) == &result);
        check(lab_echo_self == dispatcher && lab_echo_phase == 3 && lab_echo_timeout == -1);
        check(result.code == 2 && result.detail == 654 && GetLastError() == 6789);
    }
    check(FakeJump(0xC24050, reinterpret_cast<const void*>(&FakeSessionDispatch)));
    check(FakeJump(0xB833E0, reinterpret_cast<const void*>(&FakeSessionDispatch)));
    check(FakeJump(0xC25610, reinterpret_cast<const void*>(&FakeSessionDispatch)));
    check(FakeJump(0xC22790, reinterpret_cast<const void*>(&FakeSessionDispatch)));
    check(FakeJump(0xB86710, reinterpret_cast<const void*>(&FakeSessionDispatch)));
    for (int code : {1, 2, 0, -1000000, -999912}) {
        NativeResult result{}; unsigned char manager[4]{}, event[4]{}; lab_join_code = code;
        check(ObserveLabSessionDispatch(manager, nullptr, &result, event) == &result);
        check(result.code == code && result.detail == 987 && GetLastError() == 6789);
        check(lab_dispatch_arguments[0] == manager && lab_dispatch_arguments[1] == &result && lab_dispatch_arguments[2] == event);
        check(ObserveLabTicketReceived(manager, nullptr, &result, event) == &result);
        check(result.code == code && result.detail == 987 && GetLastError() == 6789);
        check(lab_dispatch_arguments[0] == manager && lab_dispatch_arguments[1] == &result && lab_dispatch_arguments[2] == event);
        check(ObserveLabPlayerTicket(manager, nullptr, &result, event) == &result);
        check(result.code == code && result.detail == 987 && GetLastError() == 6789);
        check(lab_dispatch_arguments[0] == manager && lab_dispatch_arguments[1] == &result && lab_dispatch_arguments[2] == event);
        check(ObserveLabPlayerRequest(manager, nullptr, &result, event) == &result);
        check(result.code == code && result.detail == 987 && GetLastError() == 6789);
        check(lab_dispatch_arguments[0] == manager && lab_dispatch_arguments[1] == &result && lab_dispatch_arguments[2] == event);
        check(ObserveLabTicketRequest(manager, nullptr, &result, event) == &result);
        check(result.code == code && result.detail == 987 && GetLastError() == 6789);
        check(lab_dispatch_arguments[0] == manager && lab_dispatch_arguments[1] == &result && lab_dispatch_arguments[2] == event);
    }
    lab_join_code = 1;
    check(FakeJump(0xCFA5E0, reinterpret_cast<const void*>(&FakeHostEventRoute)));
    check(FakeJump(0xC9A280, reinterpret_cast<const void*>(&FakeHostEventType)));
    for(int match : {0,1}) {
        lab_join_code=match;
        check(ObserveLabHostJoinEventType(reinterpret_cast<void*>(11),nullptr,22,33)==(match==1));
        check(lab_ticket_words[0]==11 && lab_ticket_words[1]==22 && lab_ticket_words[2]==33 && GetLastError()==6789);
    }
    for(int code : {1,2,0,-999996,-1000000,-999912}) {
        lab_join_code=code; NativeResult result{};
        check(ObserveLabHostEventRoute(reinterpret_cast<void*>(11),nullptr,&result,22,reinterpret_cast<void*>(33),44)==&result);
        check(result.code==code && result.detail==123 && GetLastError()==6789);
        check(lab_ticket_words[0]==11 && lab_ticket_words[1]==22 && lab_ticket_words[2]==33 && lab_ticket_words[3]==44);
    }
    lab_join_code = 1;
    check(FakeJump(0xC0A8B0, reinterpret_cast<const void*>(&FakeTicketLookup)));
    check(FakeJump(0xED3070, reinterpret_cast<const void*>(&FakeHostJoinGate)));
    for (uintptr_t returned : {0u, 123u}) {
        lab_ticket_return=returned;
        check(ObserveLabTicketSessionLookup(reinterpret_cast<void*>(11), nullptr, 22) == reinterpret_cast<void*>(returned));
        check(lab_ticket_words[0]==11 && lab_ticket_words[1]==22 && GetLastError()==6789);
    }
    for (int gate : {0,1}) {
        unsigned char handler[0xc4]{}; handler[0xc0]=static_cast<unsigned char>(gate); unsigned char event[4]{};
        ObserveLabHostJoinGate(handler,nullptr,event);
        check(lab_dispatch_arguments[0]==handler && lab_dispatch_arguments[1]==event && GetLastError()==6789 && handler[0xc0]==gate);
    }
    check(FakeJump(0xC223F0, reinterpret_cast<const void*>(&FakeTicketResultWords)));
    check(FakeJump(0xC15E80, reinterpret_cast<const void*>(&FakeTicketResultWords)));
    for (int code : {2,1,0,-999912}) {
        NativeResult result{}; lab_join_code = code;
        const uintptr_t expected[] = {11,reinterpret_cast<uintptr_t>(&result),33,44,55,66,77,88};
        check(ObserveLabTicketSeven<0xC223F0>(reinterpret_cast<void*>(11), nullptr, &result, 33,44,55,66,77,88) == &result);
        check(result.code == code && result.detail == 123 && GetLastError() == 6789 && memcmp(lab_ticket_words,expected,sizeof(expected)) == 0);
        check(ObserveLabTicketSeven<0xC15E80>(reinterpret_cast<void*>(11), nullptr, &result, 33,44,55,66,77,88) == &result);
        check(result.code == code && result.detail == 123 && GetLastError() == 6789 && memcmp(lab_ticket_words,expected,sizeof(expected)) == 0);
    }
    lab_join_code = 1;
    check(FakeJump(0xC2BEB0, reinterpret_cast<const void*>(&FakeTicketWords)));
    check(FakeJump(0xC0BAE0, reinterpret_cast<const void*>(&FakeTicketWords)));
    for (uintptr_t returned : {0u, 123u}) {
        lab_ticket_return = returned;
        check(ObserveLabTicketTransport(reinterpret_cast<void*>(11), nullptr, 22, 33, 44, 55, 66, 77, 88) == returned);
        check(GetLastError() == 6789);
        const uintptr_t expected[] = {11,22,33,44,55,66,77,88};
        check(memcmp(lab_ticket_words, expected, sizeof(expected)) == 0);
        ObserveLabTicketEvent(reinterpret_cast<void*>(11), nullptr, 22, 33, 44, 55, 66, 77, 88);
        check(GetLastError() == 6789 && memcmp(lab_ticket_words, expected, sizeof(expected)) == 0);
    }
    for (int code : {2,1,0,-999912}) {
        NativeResult result{code, 123}; SetLastError(9012);
        check(ObserveLabTicketLinkResult(&result, nullptr) == code && result.detail == 123 && GetLastError() == 9012);
    }
    check(FakeJump(0x6576D0, reinterpret_cast<const void*>(&FakeLabDiagnosticCtor)));
    check(FakeJump(0x657E70, reinterpret_cast<const void*>(&FakePlayerReason)));
    for (uintptr_t literal : {0x10888D8u, 0x10888E8u, 0x10888C8u}) {
        unsigned char output[32]{}; const char* text = Native<const char*>(literal);
        check(ObserveLabPlayerReason(output, nullptr, text, 13) == output);
        check(lab_rejection_literal == text && lab_reason_length == 13 && GetLastError() == 6789 && output[0] == 0);
        check(ObserveLabTicketReferenceMissing(output, nullptr, text, 0) == output);
        check(lab_rejection_literal == text && lab_reason_length == 0 && GetLastError() == 6789 && output[0] == 0);
        check(ObserveLabTicketStateRejection(output, nullptr, text, 0) == output);
        check(lab_rejection_literal == text && lab_reason_length == 0 && GetLastError() == 6789 && output[0] == 0);
        check(ObserveLabTicketRejection(output, nullptr, text) == output);
        check(lab_rejection_literal == text && GetLastError() == 6789 && output[0] == 0);
    }
    const struct { uintptr_t caller; const char* label; } ticket_reasons[] = {
        {0xC24C0E, "lab-native-ticket-session-state-rejected"},
        {0xC24CA2, "lab-native-ticket-session-flag-rejected"},
        {0xC24D41, "lab-native-ticket-empty-peer-rejected"},
        {0xC24DD6, "lab-native-ticket-transport-pool-exhausted"},
        {0xC24E27, "lab-native-ticket-add-host-failed"},
        {0xC24E8B, "lab-native-ticket-existing-request"},
        {0xC24F11, "lab-native-ticket-pool-exhausted"},
        {0xC25143, "lab-native-ticket-no-ready-peer"},
        {0xC252C3, "lab-native-ticket-host-reference-rejected"},
        {0, "lab-native-ticket-rejection-unclassified"}
    };
    for (const auto& reason : ticket_reasons)
        check(strcmp(LabTicketRejectionLabel(reason.caller), reason.label) == 0);
    for (uintptr_t literal : {0x108DAD0u, 0x108DB10u, 0x108DC4Cu, 0x108DC78u, 0x108DCA4u, 0x108DCDCu, 0x108DD04u, 0x10888F8u}) {
        unsigned char owned_output[32]{};
        auto* text = Native<const char*>(literal);
        check(ObserveLabSessionRejection(owned_output, nullptr, text) == owned_output
            && lab_rejection_literal == text && owned_output[0] == 0 && GetLastError() == 6789);
    }
    for (int result_code : {1, 2, 0, -1000000, -999985, -999977, -999920, -123}) {
        lab_join_code = result_code; NativeResult result{};
        check(ObserveLabJoinRequest(&result, reinterpret_cast<void*>(11), reinterpret_cast<void*>(22),
            reinterpret_cast<void*>(33), reinterpret_cast<void*>(44), reinterpret_cast<void*>(55), 66) == &result);
        check(result.code == result_code && result.detail == 123 && GetLastError() == 6789);
        SetLastError(9012);
        check(ObserveLabJoinCompletion(&result, nullptr) == result_code
            && result.code == result_code && result.detail == 123 && GetLastError() == 9012);
        check(lab_join_arguments[0] == 11 && lab_join_arguments[1] == 22 && lab_join_arguments[2] == 33
            && lab_join_arguments[3] == 44 && lab_join_arguments[4] == 55 && lab_join_arguments[5] == 66);
    }
#endif
    local_connect_probe = true;
    std::vector<const Patch*> selected;
    for (const auto& patch : Patches) selected.push_back(&patch);
    for (const auto& patch : ConnectPatches) selected.push_back(&patch);
    for (const auto* patch : selected) {
        auto* at = PatchAddress(*patch);
        const size_t length = patch->pointer_slot ? 4 : (patch->raw_length ? patch->raw_length : 5);
        at[-1] = 0xa5; at[length] = 0x5a;
        if (patch->pointer_slot) {
            uint32_t original = OriginalPointer(*patch); memcpy(at, &original, 4);
        } else memcpy(at, patch->original, length);
    }
    DWORD old = 0;
    if (!VirtualProtect(memory, ExpectedImageSize, PAGE_READONLY, &old)) return 2;
    check(Install());
    for (const auto* patch : selected) {
        auto* at = PatchAddress(*patch);
        const size_t length = patch->pointer_slot ? 4 : (patch->raw_length ? patch->raw_length : 5);
        check(at[-1] == 0xa5 && at[length] == 0x5a);
        uint32_t actual = 0;
        if (patch->raw_length) check(memcmp(at, patch->replacement, length) == 0);
        else if (patch->pointer_slot) memcpy(&actual, at, 4);
        else { check(at[0] == 0xe8); memcpy(&actual, at + 1, 4); actual += static_cast<uint32_t>(reinterpret_cast<uintptr_t>(at) + 5); }
        if (!patch->raw_length) check(actual == reinterpret_cast<uintptr_t>(patch->replacement));
        MEMORY_BASIC_INFORMATION info{};
        check(VirtualQuery(at, &info, sizeof(info)) && info.Protect == PAGE_READONLY);
        check(WritePatch(*patch, true));
        if (patch->pointer_slot) { memcpy(&actual, at, 4); check(actual == OriginalPointer(*patch)); }
        else check(memcmp(at, patch->original, length) == 0);
    }
    // Change the last pointer guard: the preflight must fail before any earlier
    // CALL is rewritten, regardless of which optional patches were selected.
    const Patch& last = *selected.back();
    auto* at = PatchAddress(last);
    VirtualProtect(at, 4, PAGE_READWRITE, &old);
    uint32_t bad = 0; memcpy(at, &bad, 4);
    DWORD ignored = 0; VirtualProtect(at, 4, old, &ignored);
    check(!Install() && error_code == ChangedCallsite);
    for (const auto& patch : Patches) check(memcmp(PatchAddress(patch), patch.original, patch.raw_length ? patch.raw_length : 5) == 0);
    check(!LocalContentLocked(nullptr));
    // Baseline mode ignores the opt-in connection table.
    local_connect_probe = false;
    check(Install());
    memcpy(&bad, at, 4); check(bad == 0);
    for (const auto& patch : Patches) check(WritePatch(patch, true));
    // Pump gating must not call any game function on the disabled path, a
    // foreign thread, recursion, a resumed natural tick or incomplete objects.
    initialization = 2;
    bootstrap_thread = GetCurrentThreadId();
    PumpOfflineBootstrap(); check(!pump_active);
    local_connect_probe = true;
    bootstrap_thread = 0;
    PumpOfflineBootstrap(); check(!pump_active);
    bootstrap_thread = GetCurrentThreadId();
    pump_active = true;
    PumpOfflineBootstrap(); check(pump_active);
    pump_active = false; natural_updates_seen = true;
    PumpOfflineBootstrap(); check(!pump_active);
    natural_updates_seen = false;
    PumpOfflineBootstrap(); check(!pump_active); // Null network.
    VirtualProtect(memory, ExpectedImageSize, PAGE_READWRITE, &old);
    // The local-start decision is scoped to its exact platform instance,
    // thread and explicit opt-in. It never changes the platform's offline bit.
    alignas(4) unsigned char policy[0x84]{};
    *Native<void**>(0x13789D0) = policy;
    check(SkipLocalNetworkStartup(nullptr, nullptr));
    check(SkipLocalNetworkStartup(policy, nullptr)); // Unknown platform type.
    *reinterpret_cast<uintptr_t*>(policy) = image_base + 0x112BE3C - PreferredBase;
    policy[0x80] = 1;
    check(!SkipLocalNetworkStartup(policy, nullptr) && policy[0x80] == 1);
    local_connect_probe = false;
    check(SkipLocalNetworkStartup(policy, nullptr) && policy[0x80] == 1);
    local_connect_probe = true; initialization = 1;
    check(SkipLocalNetworkStartup(policy, nullptr));
    initialization = 2; bootstrap_thread = 0;
    check(SkipLocalNetworkStartup(policy, nullptr));
    bootstrap_thread = GetCurrentThreadId();
    *Native<void**>(0x13789D0) = nullptr;
    check(SkipLocalNetworkStartup(policy, nullptr));
    *Native<void**>(0x13789D0) = policy;
    policy[0x80] = 0;
    check(!SkipLocalNetworkStartup(policy, nullptr) && policy[0x80] == 0);
    *Native<void**>(0x13789D0) = nullptr;
    alignas(4) unsigned char network[0xa1c]{};
    alignas(4) unsigned char owner[0x2a8]{};
    *Native<unsigned char**>(0x1379E14) = network;
    PumpOfflineBootstrap(); check(!pump_active); // Null owner.
    *reinterpret_cast<unsigned char**>(network + 0xa18) = owner;
    PumpOfflineBootstrap(); check(!pump_active); // Wrong owner table.
    *reinterpret_cast<uintptr_t*>(owner) = image_base + 0x10919BC - PreferredBase;
    PumpOfflineBootstrap(); check(!pump_active); // Wrong RV table.
    *reinterpret_cast<uintptr_t*>(owner + 0x50) = image_base + 0x109C9D8 - PreferredBase;
    PumpOfflineBootstrap(); check(!pump_active); // Missing facade.
    *reinterpret_cast<void**>(owner + 0xa4) = owner;
    PumpOfflineBootstrap(); check(!pump_active); // Missing update dependencies.
    alignas(4) unsigned char facade[0x24]{};
    *reinterpret_cast<void**>(owner + 0xa4) = facade;
    check(!LocalConnectionReady(nullptr) && !LocalConnectionReady(owner));
    check(!LocalConnectionReady(network)); // Disconnected.
    owner[0x88] = 1; owner[0x98] = 1;
    check(!LocalConnectionReady(network)); // Pending cannot claim readiness.
    owner[0x98] = 0;
    check(LocalConnectionReady(network));
    local_connect_probe = false;
    check(!LocalConnectionReady(network));
    local_connect_probe = true; initialization = 1;
    check(!LocalConnectionReady(network));
    initialization = 2;
    *reinterpret_cast<void**>(facade + 0x0c) = owner;
    check(!LocalConnectionReady(network)); // Borrowed Ubi facade is not local.
    *reinterpret_cast<void**>(facade + 0x0c) = nullptr;
    *reinterpret_cast<uintptr_t*>(owner + 0x50) = 0;
    check(!LocalConnectionReady(network));
    *reinterpret_cast<uintptr_t*>(owner + 0x50) = image_base + 0x109C9D8 - PreferredBase;
    *reinterpret_cast<uintptr_t*>(owner) = 0;
    check(!LocalConnectionReady(network));

    // Exercise the production pump against synthetic native objects and x86
    // trampoline stubs. This verifies actual calling conventions, dispatch
    // order, fallback suppression and callback-driven teardown, without S7.
    *reinterpret_cast<uintptr_t*>(owner) = image_base + 0x10919BC - PreferredBase;
    *reinterpret_cast<void**>(owner + 0x100) = owner;
    *reinterpret_cast<void**>(owner + 0x104) = owner;
    *reinterpret_cast<void**>(owner + 0x110) = owner;
    owner[0x78] = 1; // A real connection is already requested in this fixture.
    pump_network = network; pump_owner = owner;
    check(FakeJump(0xE82240, reinterpret_cast<const void*>(&FakeNetworkGetter)));
    check(FakeJump(0xC956C0, reinterpret_cast<const void*>(&FakeOwnerUpdate)));
    check(FakeJump(0xED3BA0, reinterpret_cast<const void*>(&FakeMasterUpdate)));
    check(FakeJump(0xCBC710, reinterpret_cast<const void*>(&FakeCoreUpdate)));
    auto trace_is = [&](const char* expected) {
        return pump_trace.size() == strlen(expected) &&
            (pump_trace.empty() || memcmp(pump_trace.data(), expected, pump_trace.size()) == 0);
    };
    PumpOfflineBootstrap(); check(trace_is("O") && !pump_active);
    alignas(4) unsigned char core[0x24]{};
    alignas(4) unsigned char implementation[8]{};
    *reinterpret_cast<void**>(network + 0x2c) = core;
    check(!LocalUpdateCore(network)); // Unknown core type.
    *reinterpret_cast<uintptr_t*>(core) = image_base + 0x10940A0 - PreferredBase;
    check(!LocalUpdateCore(network)); // Master not constructed.
    *reinterpret_cast<uintptr_t*>(network + 0x5c) = image_base + 0x1091E3C - PreferredBase;
    check(!LocalUpdateCore(network)); // Master not registered with the core.
    *reinterpret_cast<void**>(network + 0x5c + 0x4c0) = core;
    check(!LocalUpdateCore(network)); // Missing implementation.
    *reinterpret_cast<void**>(core + 0x20) = implementation;
    check(!LocalUpdateCore(network)); // Unknown implementation type.
    *reinterpret_cast<uintptr_t*>(implementation) = image_base + 0x1099548 - PreferredBase;
    check(!LocalUpdateCore(network)); // Missing scheduler.
#ifdef S7_LOCAL_PAIR_LAB
    alignas(4) unsigned char scheduler[0xc0]{};
    *reinterpret_cast<void**>(implementation + 4) = scheduler;
    check(!LocalUpdateCore(network)); // Reject unknown scheduler before reading its frame.
    *reinterpret_cast<uintptr_t*>(scheduler) = image_base + 0x109959C - PreferredBase;
    pump_scheduler = scheduler;
#else
    *reinterpret_cast<void**>(implementation + 4) = implementation;
#endif
    check(LocalUpdateCore(network) == core);
    udp_port = 10001;
    check(!LocalSessionSearchReady(network)); // No successful native startup.
    network[0x5c + 0x4c4] = 1;
    owner[0x18] = 1; owner[0x38] = 1;
    *reinterpret_cast<int32_t*>(owner + 0x28) = 1;
    check(!LocalSessionSearchReady(network)); // Missing search helper.
    *reinterpret_cast<void**>(owner + 0x108) = owner;
    check(LocalSessionSearchReady(network) && owner[0x3a] == 0);
    for (auto* flag : {network + 0x5c + 0x4c4, owner + 0x18, owner + 0x38, owner + 0x88}) {
        *flag = 0; check(!LocalSessionSearchReady(network)); *flag = 1;
    }
    for (int32_t result : {-1, 0, 2}) {
        *reinterpret_cast<int32_t*>(owner + 0x28) = result;
        check(!LocalSessionSearchReady(network));
    }
    *reinterpret_cast<int32_t*>(owner + 0x28) = 1;
    owner[0x249] = 1; check(!LocalSessionSearchReady(network)); owner[0x249] = 0;
    owner[0x98] = 1; check(!LocalSessionSearchReady(network)); owner[0x98] = 0;
    udp_port = 0; check(!LocalSessionSearchReady(network)); udp_port = 10001;
    local_connect_probe = false; check(!LocalSessionSearchReady(network)); local_connect_probe = true;
    bootstrap_thread = 0; check(!LocalSessionSearchReady(network)); bootstrap_thread = GetCurrentThreadId();
    *reinterpret_cast<void**>(network + 0x2c) = nullptr;
    check(!LocalSessionSearchReady(network)); *reinterpret_cast<void**>(network + 0x2c) = core;
    *reinterpret_cast<void**>(facade + 0x0c) = owner;
    check(!LocalSessionSearchReady(network)); *reinterpret_cast<void**>(facade + 0x0c) = nullptr;
    check(!LocalSessionSearchReady(nullptr) && !LocalSessionSearchReady(owner));
    check(LocalSessionSearchReady(network) && owner[0x3a] == 0);
    // Check the returned native small-string layout, surrounding stack memory
    // and thiscall/fastcall callee cleanup through the actual patched target.
    struct SandboxFixture { uint32_t before; NativeSmallString value; uint32_t after; } sandbox;
    memset(&sandbox, 0xa5, sizeof(sandbox));
    using SandboxGetter = NativeSmallString* (__thiscall*)(void*, NativeSmallString*);
    check(FakeJump(0xD43F50, reinterpret_cast<const void*>(&GetLocalSearchSandbox)));
    for (int iteration = 0; iteration < 3; ++iteration) {
        check(Native<SandboxGetter>(0xD43F50)(owner + 0x50, &sandbox.value) == &sandbox.value);
        check(sandbox.before == 0xa5a5a5a5 && sandbox.after == 0xa5a5a5a5);
        check(sandbox.value.length == 0 && sandbox.value.capacity == 15 &&
            sandbox.value.inline_data[0] == 0 && sandbox.value.inline_data[15] == 0);
    }
    const auto unchanged = sandbox;
    check(!ConstructLocalSearchSandbox(nullptr, &sandbox.value));
    check(!ConstructLocalSearchSandbox(owner, &sandbox.value));
    check(!ConstructLocalSearchSandbox(owner + 0x50, nullptr));
    bootstrap_thread = 0;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    bootstrap_thread = GetCurrentThreadId(); local_connect_probe = false;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    local_connect_probe = true; initialization = 1;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    initialization = 2; owner[0x98] = 1;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    owner[0x98] = 0; *reinterpret_cast<void**>(facade + 0x0c) = owner;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    *reinterpret_cast<void**>(facade + 0x0c) = nullptr;
    check(memcmp(&sandbox, &unchanged, sizeof(sandbox)) == 0);
    alignas(4) unsigned char search_helper[0x1dc]{};
    alignas(4) unsigned char backend[0xe8]{};
    *reinterpret_cast<void**>(owner + 0x108) = search_helper;
    check(!EnsureLocalSearchSpace(network)); // Reject unknown helper type.
    *reinterpret_cast<uintptr_t*>(search_helper) = image_base + 0x109CB58 - PreferredBase;
    check(!EnsureLocalSearchSpace(network)); // Missing private context.
    *reinterpret_cast<void**>(search_helper + 0x1d8) = search_helper;
    check(!EnsureLocalSearchSpace(network)); // Missing backend.
    check(!QueryLocalSessionCreate(network, nullptr));
    check(!QueryLocalSessionJoin(network, nullptr));
    *reinterpret_cast<void**>(facade + 0x20) = backend;
    check(!EnsureLocalSearchSpace(network)); // Missing public space string.
    *reinterpret_cast<const char**>(backend + 0xe4) = "";
    check(!EnsureLocalSearchSpace(network));
    char too_long[130]; memset(too_long, 'x', sizeof(too_long)); too_long[129] = 0;
    *reinterpret_cast<const char**>(backend + 0xe4) = too_long;
    check(!EnsureLocalSearchSpace(network));
    *reinterpret_cast<const char**>(backend + 0xe4) = "invalid space";
    check(!EnsureLocalSearchSpace(network) && search_space_calls == 0);
    check(FakeJump(0xD4A860, reinterpret_cast<const void*>(&FakeSetSearchSpace)));
    auto* bound_space = reinterpret_cast<NativeSmallString*>(search_helper + 0x10);
    for (const char* value : {"local-s7", "12345678-1234-1234-1234-123456789abc"}) {
        *bound_space = {}; bound_space->capacity = 15;
        *reinterpret_cast<const char**>(backend + 0xe4) = value;
        const int before = search_space_calls;
        check(EnsureLocalSearchSpace(network));
        check(SameSearchSpace(*bound_space, value, strlen(value)));
        check(EnsureLocalSearchSpace(network) && search_space_calls == before + 1);
        check(QueryLocalSessionCreate(network, nullptr) && search_space_calls == before + 1);
        check(QueryLocalSessionJoin(network, nullptr) && search_space_calls == before + 1);
        const unsigned char original_nat = owner[0x3a];
        local_connect_probe = false;
        check(!QueryLocalSessionCreate(network, nullptr));
        check(!QueryLocalSessionJoin(network, nullptr));
        local_connect_probe = true;
        bootstrap_thread = 0;
        check(!QueryLocalSessionCreate(network, nullptr));
        check(!QueryLocalSessionJoin(network, nullptr));
        bootstrap_thread = GetCurrentThreadId();
        owner[0x88] = 0;
        check(!QueryLocalSessionCreate(network, nullptr));
        check(!QueryLocalSessionJoin(network, nullptr));
        owner[0x88] = 1;
        check(QueryLocalSessionCreate(network, nullptr) && owner[0x3a] == original_nat);
        check(QueryLocalSessionJoin(network, nullptr) && owner[0x3a] == original_nat);
        *reinterpret_cast<const char**>(backend + 0xe4) = "different-space";
        check(!EnsureLocalSearchSpace(network) && search_space_calls == before + 1);
        check(!QueryLocalSessionCreate(network, nullptr));
        check(!QueryLocalSessionJoin(network, nullptr));
    }
    *bound_space = {}; bound_space->capacity = 15;
    *reinterpret_cast<const char**>(backend + 0xe4) = "local-s7";
    search_space_mode = 1;
    check(!EnsureLocalSearchSpace(network)); // Setter tears down ownership.
    *Native<unsigned char**>(0x1379E14) = network;
    *bound_space = {}; bound_space->capacity = 15; search_space_mode = 2;
    check(!EnsureLocalSearchSpace(network)); // Setter did not preserve namespace.
    search_space_mode = 0;
    for (int mode = 0; mode <= 8; ++mode) {
        pump_mode = mode; pump_trace.clear(); network_getter_calls = 0;
        *Native<unsigned char**>(0x1379E14) = network;
        *reinterpret_cast<void**>(network + 0xa18) = owner;
        *reinterpret_cast<void**>(network + 0x2c) = core;
        PumpOfflineBootstrap();
        check(trace_is(mode < 2 || mode == 8 ? "MCO" : mode < 5 ? "M" : "MC"));
        check(!pump_active && !natural_updates_seen);
        if (mode == 8) check(network_getter_calls == 1); // No post-destruction owner work.
    }
    *Native<unsigned char**>(0x1379E14) = network;
    *reinterpret_cast<void**>(network + 0xa18) = owner;
    *reinterpret_cast<void**>(network + 0x2c) = core;
    pump_mode = 0;
#ifdef S7_LOCAL_PAIR_LAB
    alignas(4) unsigned char manager[4]{};
    *reinterpret_cast<uintptr_t*>(manager) = image_base + 0x10934EC - PreferredBase;
    check(FakeJump(0xCA6380, reinterpret_cast<const void*>(&FakeManagerUpdate)));
    for (int mode : {0, 9, 10, 11, 12}) {
        *Native<unsigned char**>(0x1379E14) = network;
        *reinterpret_cast<void**>(owner + 0x100) = manager;
        pump_mode = mode; pump_trace.clear();
        auto before = manager_update_count;
        PumpOfflineBootstrap();
        check(trace_is(mode == 9 ? "MJCO" : mode == 10 || mode == 0 ? "MCJO" : "MCJ"));
        check(manager_update_count == before + 1 && !pump_active && !natural_updates_seen);
    }
    *Native<unsigned char**>(0x1379E14) = network;
    *reinterpret_cast<void**>(owner + 0x100) = manager;
    check(FakeJump(0xBAF5D0, reinterpret_cast<const void*>(&FakeEchoUpdate)));
    NativeResult echo_result{};
    auto echo_before = echo_update_count;
    check(UpdateLabEcho(&echo_result, 3, -1) == &echo_result && echo_result.code == 2 && echo_result.detail == 78);
    check(echo_update_count == echo_before + 1);
    network[0x5c + 0x4c7] = 1;
    *reinterpret_cast<unsigned int*>(network + 0x5c + 0x400) = 1;
    for (int mode : {0, 13, 14, 15}) {
        *Native<unsigned char**>(0x1379E14) = network;
        *reinterpret_cast<void**>(network + 0x2c) = core;
        pump_mode = mode; pump_trace.clear(); echo_before = echo_update_count;
        PumpOfflineBootstrap();
        check(trace_is(mode == 0 ? "MCEJO" : mode == 15 ? "MECJO" : "MCE"));
        check(echo_update_count == echo_before + 1 && !pump_active);
    }
    *Native<unsigned char**>(0x1379E14) = network;
    *reinterpret_cast<void**>(network + 0x2c) = core;
    pump_mode = 0; pump_trace.clear();
    *reinterpret_cast<unsigned int*>(network + 0x5c + 0x400) = 2;
    PumpOfflineBootstrap(); check(trace_is("MCJO"));
    network[0x5c + 0x4c7] = 0;
    *reinterpret_cast<unsigned int*>(network + 0x5c + 0x400) = 1;
    check(FakeJump(0xCB90C0, reinterpret_cast<const void*>(&FakeCoreBoundary)));
    for (int mode : {0, 16, 17, 18}) {
        *Native<unsigned char**>(0x1379E14) = network;
        *reinterpret_cast<void**>(network + 0x2c) = core;
        network[0x30] = 1; network[0x5c + 0x4c7] = 1;
        pump_mode = mode; pump_trace.clear();
        PumpOfflineBootstrap();
        check(trace_is(mode == 0 ? "PMQCEJO" : mode == 16 ? "P" : mode == 17 ? "PMQ" : "PMCEJO"));
        check(!pump_active && !natural_updates_seen);
    }
    *Native<unsigned char**>(0x1379E14) = network;
    *reinterpret_cast<void**>(network + 0x2c) = core;
    network[0x30] = 0; network[0x5c + 0x4c7] = 0;
    pump_mode = 0; pump_trace.clear();
    UpdateLocalJoinWait(network, nullptr); check(trace_is("MCJO") && !pump_active);
    pump_mode = 11; pump_trace.clear();
    UpdateLocalJoinWait(network, nullptr); check(trace_is("MCJ") && !pump_active);
    *Native<unsigned char**>(0x1379E14) = network;
    pump_mode = 0; local_connect_probe = false; pump_trace.clear();
    UpdateLocalJoinWait(network, nullptr); check(trace_is("M"));
    local_connect_probe = true; natural_updates_seen = true; pump_trace.clear();
    UpdateLocalJoinWait(network, nullptr); check(trace_is("MCJO"));
    natural_updates_seen = false;
    bootstrap_thread = 0; pump_trace.clear();
    UpdateLocalJoinWait(network, nullptr); check(trace_is("M"));
    pump_trace.clear();
    auto manager_before = manager_update_count;
    PumpOfflineBootstrap(); check(trace_is("") && manager_update_count == manager_before);
    TickFakeManager(); check(trace_is("J") && manager_update_count == manager_before);
    bootstrap_thread = GetCurrentThreadId();
    *reinterpret_cast<void**>(owner + 0x100) = owner;
    pump_mode = 0; pump_trace.clear();
    PumpOfflineBootstrap(); check(trace_is("MCO"));
    pump_trace.clear();
    // Reproduce the live host failure: an isolated natural owner callback must
    // not permanently starve queued core work after lobby creation.
    UpdateLocalGame(owner, nullptr);
    check(natural_updates_seen);
    pending_core_tasks = 3; pump_trace.clear();
    PumpOfflineBootstrap(); check(trace_is("MCO") && pending_core_tasks == 0);
    // A genuine core tick suppresses the next fallback, then a stopped core
    // resumes on the following call. No permanent natural-update latch remains.
    NativeResult external_result{};
    pending_core_tasks = 2;
    FakeCoreUpdate(core, nullptr, &external_result, 3);
    check(pending_core_tasks == 0);
    pump_trace.clear(); PumpOfflineBootstrap(); check(trace_is(""));
    pending_core_tasks = 2;
    PumpOfflineBootstrap(); check(trace_is("MCO") && pending_core_tasks == 0);
    natural_updates_seen = false; pump_trace.clear();
#endif
    pump_trace.clear(); natural_updates_seen = true;
    PumpOfflineBootstrap();
#ifdef S7_LOCAL_PAIR_LAB
    check(trace_is("MCO")); pump_trace.clear();
#else
    check(trace_is(""));
#endif
    natural_updates_seen = false; bootstrap_thread = 0;
    PumpOfflineBootstrap(); check(trace_is(""));
    bootstrap_thread = GetCurrentThreadId(); local_connect_probe = false;
    PumpOfflineBootstrap(); check(trace_is(""));
    local_connect_probe = true;
    *reinterpret_cast<void**>(facade + 0x0c) = owner;
    PumpOfflineBootstrap(); check(trace_is("")); // Never pump a borrowed Ubi facade.
    *Native<unsigned char**>(0x1379E14) = nullptr;
    VirtualFree(memory, 0, MEM_RELEASE);
    std::printf("%s %d bootstrap patch checks\n", failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
