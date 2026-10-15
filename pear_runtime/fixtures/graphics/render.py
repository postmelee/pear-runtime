# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original independent readback and pipeline oracles for five bounded cases.

The imported constants and four function bodies are exact. See
provenance/fixture-graphics-import.json for source and license attribution.
"""
import hashlib
import json
import re
import struct

from pear_runtime.fixtures.inputs import need, digest

NAMES=('buffer','texture_copy','texture_sample','raster','depth','blend','compute')

SHADERS={'vertex':'vs_5_0','solid':'ps_5_0','sample_image':'ps_5_0','transform':'cs_5_0'}

OPERATIONS=['device','vertex','solid','sample_image','transform','vertex_shader','solid_shader','sample_shader','compute_shader',
    'buffer','buffer_staging','buffer_map','texture_upload','texture_staging','texture_map','texture_srv','point_sampler',
    'raster_state','constants','sample_target','sample_rtv','texture_staging','texture_map','raster_target','raster_rtv',
    'texture_staging','texture_map','depth_target','depth_view','depth_state','texture_staging','texture_map',
    'blend_state','texture_staging','texture_map','compute_input','compute_output','compute_srv','compute_uav','buffer_staging','buffer_map']

def validation(stderr):
    need(not re.search(rb'validation error|failed assertion|(?:shader|GPU|Metal API) validation[^\n]*(?:error|invalid|out.of.bounds)|\b(?:GPU|Shader) AddressSanitizer\b',stderr,re.I),
         'render_validation_error')

def compare(name,width,height,pitch,fmt,data):
    need(name in NAMES,'render_unknown_readback')
    if name in ('buffer','compute'):
        need((width,height,fmt)==(64,1,'uint32') and pitch>=256 and len(data)==256,'render_buffer_layout')
        values=struct.unpack('<64I',data)
        expected=[i*0x010203+5 if name=='buffer' else (i^0xa5)*3+7 for i in range(64)]
        need(list(values)==expected,'render_integer_mismatch');return 64
    size=8 if name.startswith('texture_') else 64
    need((width,height,fmt)==(size,size,'rgba8') and pitch>=size*4 and len(data)==size*size*4,'render_texture_layout')
    checked=0
    for y in range(size):
        for x in range(size):
            rgba=list(data[(y*size+x)*4:(y*size+x+1)*4]);tolerance=0
            if size==8:expected=[x*17+3,y*19+5,(x+y)*11+7,255]
            elif name=='raster':
                if 18<=x<=45 and 18<=y<=45:expected=[0,255,0,255]
                elif x<14 or x>49 or y<14 or y>49:expected=[17,34,51,255]
                else:continue
            elif name=='depth':expected=[255,0,0,255]
            else:expected=[128,0,128,128];tolerance=1
            need(all(abs(a-b)<=tolerance for a,b in zip(rgba,expected)),f'render_pixel_mismatch_{name}_{x}_{y}')
            checked+=1
    return checked

def terminal(raw):
    need(len(raw)<=1024*1024,'render_terminal_bound')
    lines=raw.decode('utf-8').splitlines()
    need(lines and json.loads(lines[0]).get('record_kind')=='pear_bootstrap_helper','render_bootstrap')
    need(lines[1]=='PEAR_RENDER_BEGIN version=1 cases=5' and lines[-1]=='PEAR_RENDER_END cases=5 readbacks=7 completed=1','render_terminal_incomplete')
    modules={};shaders={};results={};operations=[];devices=0
    for line in lines[2:-1]:
        if line=='PEAR_RENDER_DEVICE level=b000':devices+=1;continue
        m=re.fullmatch(r'PEAR_RENDER_HR operation=(\w+) hr=([0-9a-f]{8})',line)
        if m:
            need(m[2]=='00000000','render_operation_failed');operations.append(m[1]);continue
        m=re.fullmatch(r'PEAR_GRAPHICS_MODULE name=(\S+) base=([0-9a-fA-F]+) path=(.+)',line)
        if m:
            need(m[1] not in modules and int(m[2],16)>0,'render_module_duplicate')
            modules[m[1]]=dict(base=int(m[2],16),path=m[3]);continue
        m=re.fullmatch(r'PEAR_RENDER_SHADER entry=(\w+) profile=(\w+) data=([0-9a-f]+)',line)
        if m:
            need(m[1] in SHADERS and m[1] not in shaders and m[2]==SHADERS[m[1]],'render_shader_set')
            blob=bytes.fromhex(m[3]);need(blob[:4]==b'DXBC' and len(blob)>=32 and struct.unpack_from('<I',blob,24)[0]==len(blob),'render_shader_bytecode')
            shaders[m[1]]=dict(profile=m[2],sha256=digest(blob),sha1=hashlib.sha1(blob).hexdigest(),size_bytes=len(blob));continue
        m=re.fullmatch(r'PEAR_RENDER_DATA name=(\w+) width=(\d+) height=(\d+) pitch=(\d+) format=(\w+) data=([0-9a-f]+)',line)
        need(m is not None,'render_unknown_record')
        name=m[1];need(name not in results,'render_duplicate_readback');w,h,p=map(int,m.group(2,3,4));data=bytes.fromhex(m[6])
        count=compare(name,w,h,p,m[5],data)
        results[name]=dict(width=w,height=h,row_pitch=p,format=m[5],checked_elements=count,sha256=digest(data))
    need(devices==1 and set(modules)=={'d3d11.dll','dxgi.dll','winemetal.dll','d3dcompiler_47.dll'},'render_device_modules')
    need(set(shaders)==set(SHADERS) and tuple(results)==NAMES and operations==OPERATIONS,'render_incomplete_operations')
    return dict(modules=modules,shaders=shaders,readbacks=results)

def pipeline_validation(stderr,shaders):
    rows=re.findall(rb'^PEAR_METAL_PIPELINE kind=(render|compute) validation=(\d+) function=(\S+)\r?$',stderr,re.M)
    need(rows and all(state==b'1' for _,state,_ in rows),'render_pipeline_validation_disabled')
    vertex=b'vs_'+shaders['vertex']['sha1'][:8].encode()+b'_'
    compute=b'cs_'+shaders['transform']['sha1'][:8].encode()+b'_'
    render=[name.decode() for kind,_,name in rows if kind==b'render' and name.startswith(vertex)]
    dispatch=[name.decode() for kind,_,name in rows if kind==b'compute' and name.startswith(compute)]
    need(len(render)>=4 and len(dispatch)==1,'render_pipeline_instrumentation_missing')
    return dict(all_observed_enabled=True,observed_pipeline_count=len(rows),fixture_render=render,fixture_compute=dispatch)
