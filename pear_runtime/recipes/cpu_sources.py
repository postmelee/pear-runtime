# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare the canonical CPU19/ordering fixture sources without invoking tools.

The ABI assembly generator is retained from Pear tools/cpu/build.py. Its emitted
original Pear ABI assembly retains MIT notices. Compiler and native Windows
capture remain separate operations; see recipes/cpu/sources-v1.json.
"""
from pathlib import Path
import argparse
import hashlib
import json
from pear_runtime.assembly._common import load_json, read_relative, encoded
from pear_runtime.errors import need
from Pear.Tools.CPU import corpus, generate as asm_generator


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def abi_assembly(seh=False):
    regs='rbx rbp rsi rdi r12 r13 r14 r15'.split()
    a=['; SPDX-License-Identifier: MIT', '; Original Pear ABI state probe.',
       'BITS 64','DEFAULT REL','section .text code align=16',
       'extern pear_before, pear_after, pear_alignment, pear_callback_alignment',
       'extern pear_native_outer, pear_native_inner, pear_callback_body',
       'global pear_callback', 'pear_callback:',
       '    mov rax, rsp', '    and eax, 15', '    mov [rel pear_callback_alignment], rax',
       '    jmp pear_callback_body']
    if seh:
        a=['; SPDX-License-Identifier: MIT', 'BITS 64', 'DEFAULT REL',
           'section .text code align=16', 'extern pear_before, pear_after, pear_alignment',
           'extern pear_native_outer']
    for slot, name in enumerate(('outer',) if seh else ('outer','inner')):
        a += [f'global pear_abi_{name}',f'pear_abi_{name}:',
              '    mov rax, rsp', '    and eax, 15', f'    mov [rel pear_alignment + {slot*8}], rax']
        # 8 pushes leave the entry alignment unchanged. 200 local bytes include
        # 32 shadow bytes, ten XMM slots, and 8 bytes alignment padding.
        a += [f'    push {r}' for r in regs]
        a += ['    sub rsp, 200']
        a += [f'    movdqu [rsp + {32+i*16}], xmm{i+6}' for i in range(10)]
        a += [f'    mov {r}, {0x1020304050607080+i}' for i,r in enumerate(regs)]
        a += [f'    movdqu xmm{i+6}, [rel pear_patterns + {i*16}]' for i in range(10)]
        for side in ('before','after'):
            a += [f'    mov [rel pear_{side} + {slot*224+i*8}], {r}' for i,r in enumerate(regs)]
            a += [f'    movdqu [rel pear_{side} + {slot*224+64+i*16}], xmm{i+6}' for i in range(10)]
            if side=='before': a += [f'    call pear_native_{name}']
        a += [f'    movdqu xmm{i+6}, [rsp + {32+i*16}]' for i in range(10)]
        a += ['    add rsp, 200']+[f'    pop {r}' for r in reversed(regs)]+['    ret']
    a += ['section .rdata data align=16','pear_patterns:']
    a += [f'    dq {0x1122334455667700+i}, {0x8877665544332200+i}' for i in range(10)]
    return '\n'.join(a)+'\n'



def prepare(fex_root, runtime_root, output, *, recipe_path=None):
    """Generate source files using only the supplied component roots."""
    fex_root=corpus.canonical_root(fex_root)
    runtime_root=corpus.canonical_root(runtime_root)
    need(Path(asm_generator.__file__).resolve().parents[3]==fex_root,
         'cpu_generator_source_root')
    need(Path(__file__).resolve().parents[2]==runtime_root,'cpu_runtime_source_root')
    recipe_path=Path(recipe_path) if recipe_path is not None else runtime_root/'recipes/cpu/sources-v1.json'
    recipe_raw=read_relative(recipe_path.parent,recipe_path.name)
    recipe=load_json(recipe_path)
    need(recipe.get('schema_version')==1 and recipe.get('scope')=='cpu_fixture_source_recipe',
         'cpu_source_recipe')
    roots={'fex':fex_root,'runtime':runtime_root}
    inputs=[]
    for row in recipe['inputs']:
        need(row['root'] in roots,'cpu_source_input_root')
        raw=read_relative(roots[row['root']],row['path'])
        need(digest(raw)==row['sha256'] and len(raw)==row['size_bytes'],'cpu_source_input_changed')
        inputs.append(dict(row))
    output=corpus.fresh_output(output)
    contract_root=fex_root/'Pear/Tests/CPU'
    # Preflight the complete source corpus before creating any output directory.
    manifest=load_json(contract_root/'corpus.json');sources=load_json(contract_root/'sources.json')
    inventory=corpus.assess(fex_root,manifest,sources,contract_root=contract_root,boundary_root=runtime_root)
    output.mkdir()
    generated=asm_generator.generate(fex_root,output/'sources',
                                    boundary_root=runtime_root,contract_root=contract_root)
    (output/'sources/abi.asm').write_text(abi_assembly())
    (output/'sources/seh.asm').write_text(abi_assembly(seh=True))
    copied=[]
    for row in inputs:
        if row['root']=='runtime' and row['path'].endswith(('.c','.asm')):
            path=output/'corresponding-source'/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
            raw=read_relative(runtime_root,row['path'])
            need(digest(raw)==row['sha256'],'cpu_source_changed_during_generation')
            path.write_bytes(raw);copied.append(str(path.relative_to(output)))
    files=[]
    for path in sorted(output.rglob('*')):
        if path.is_file():
            raw=path.read_bytes();files.append(dict(path=str(path.relative_to(output)),
                sha256=digest(raw),size_bytes=len(raw)))
    for row in inputs:
        raw=read_relative(roots[row['root']],row['path'])
        need(digest(raw)==row['sha256'] and len(raw)==row['size_bytes'],'cpu_source_changed_during_generation')
    need(read_relative(recipe_path.parent,recipe_path.name)==recipe_raw,'cpu_recipe_changed')
    result=dict(schema_version=1,scope='cpu_fixture_source_preparation',passed=True,
        source_roots={k:str(v) for k,v in roots.items()},recipe_sha256=digest(recipe_raw),
        producer_sha256=digest(Path(__file__).read_bytes()),inputs=inputs,
        asm_cases=len(generated['cases']),cpu_pe_cases=len(manifest['cases'])+
            sum(c['stage']==2 for c in manifest['boundaries']),ordering_budget=recipe['ordering_budget'],
        source_inventory={k:v for k,v in inventory.items() if k!='census'},
        files=files,compiler_execution=False,native_execution=False,cpu_qualified=False,game_qualified=False)
    (output/'preparation.json').write_bytes(encoded(result))
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fex-root',type=Path,required=True)
    parser.add_argument('--runtime-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--recipe',type=Path)
    args=parser.parse_args(argv)
    result=prepare(args.fex_root,args.runtime_root,args.output,recipe_path=args.recipe)
    print(json.dumps(dict(passed=result['passed'],asm_cases=result['asm_cases'],
                         cpu_pe_cases=result['cpu_pe_cases'],compiler_execution=False,native_execution=False)))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
