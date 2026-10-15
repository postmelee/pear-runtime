# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Canonical shared Abort header; historical patch preparation is excluded."""
from . import abort_observation as schema

def header():
    fields=list(dict.fromkeys(k for fields in schema.FIELDS.values() for k in fields))
    text='#pragma once\n#include <stdint.h>\n#include <stdio.h>\n// Private diagnostic payload, not the Wine/FEX request ABI.\nstruct PearAbortRecord {\n'
    text+=''.join('  '+('int64_t' if k=='code' else 'uint64_t')+' '+k+';\n' for k in fields)+'};\n'
    text+='static inline int pear_abort_format(char *buffer, size_t size, unsigned side, const struct PearAbortRecord *d) {\n'
    for n,(side,fields) in enumerate(schema.FIELDS.items(),1):
        fmt='PEAR_ABORT1 side='+side+' '+ ' '.join(k+'=%'+('lld' if k=='code' else 'llu') for k in fields)+'\\n'
        args=','.join('('+('long long' if k=='code' else 'unsigned long long')+')d->'+k for k in fields)
        text+=f'  if (side=={n}) return snprintf(buffer,size,"{fmt}",{args});\n'
    return text+'''  return -1;
}
#ifdef __cplusplus
extern "C" bool PearAbortEnabled();
extern "C" void PearAbortEmit(unsigned, const PearAbortRecord*);
extern "C" uint64_t PearAbortBegin(const PearAbortRecord*);
#endif
'''


if __name__ == "__main__":
    import sys
    sys.stdout.write(header())
