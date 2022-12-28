#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "mmpriv.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string prefix = provider.ConsumeRandomLengthString(1000);
    int n_splits = provider.ConsumeIntegralInRange<int>(1, 1000);

    mm_split_rm_tmp(prefix.c_str(), n_splits);

    return 0;
}
