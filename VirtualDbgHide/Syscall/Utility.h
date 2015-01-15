#pragma once

ULONG_PTR GetNtoskrnlBase();
ULONG_PTR GetSSDTBase();
ULONG_PTR GetSSDTEntry(ULONG TableIndex);