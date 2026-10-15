# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original presentation/18-frame oracles with an explicit capture producer.

visible/visible_frames require the separately admitted original capture producer
path as their last argument. No screen capture or launcher is implemented here.
pixels decodes only an already-owned PNG via macOS frameworks when called.
"""
from pathlib import Path
import ctypes
import json
import re
from pear_runtime.fixtures.inputs import fact, read, need
from pear_runtime.fixtures.graphics.render import validation

def terminal(raw):
    lines=raw.decode().splitlines();need(lines and json.loads(lines.pop(0)).get('record_kind')=='pear_bootstrap_helper','present_bootstrap')
    need(lines.pop(0)=='PEAR_PRESENT_BEGIN version=1 cycles=3 frames=18' and lines.pop()=='PEAR_PRESENT_END cycles=3 frames=18 passed=1','present_terminal')
    frames=[];cycles=[];ready=[];sizes=[];modules={};operations={i:[] for i in range(1,4)}
    for line in lines:
        m=re.fullmatch(r'PEAR_PRESENT_HR cycle=([123]) operation=(\w+) hr=00000000',line)
        if m:operations[int(m[1])].append(m[2]);continue
        m=re.fullmatch(r'PEAR_GRAPHICS_MODULE name=(\S+) base=([0-9a-fA-F]+) path=(.+)',line)
        if m:
            need(m[1] not in modules and int(m[2],16)>0,'present_module_duplicate');modules[m[1]]=dict(base=int(m[2],16),path=m[3]);continue
        m=re.fullmatch(r'PEAR_PRESENT_FRAME cycle=(\d+) phase=(\d+) frame=(\d+) width=(\d+) height=(\d+) gpu=1',line)
        if m:frames.append(tuple(map(int,m.groups())));continue
        m=re.fullmatch(r'PEAR_PRESENT_READY cycle=(\d+) phase=(\d+) width=(\d+) height=(\d+)',line)
        if m:ready.append(tuple(map(int,m.groups())));continue
        m=re.fullmatch(r'PEAR_PRESENT_SIZE cycle=(\d+) width=(\d+) height=(\d+) count=(\d+)',line)
        if m:sizes.append(tuple(map(int,m.groups())));continue
        m=re.fullmatch(r'PEAR_PRESENT_CYCLE cycle=(\d+) resize_callbacks=(\d+) destroy_callbacks=1',line)
        need(m is not None,'present_unexpected_terminal');cycles.append(tuple(map(int,m.groups())))
    expected=[(c,p,f,96 if p==1 else 64,80 if p==1 else 64) for c in (1,2,3) for p in range(3) for f in range(2)]
    need(frames==expected and ready==[r[:2]+r[3:] for r in expected[::2]],'present_frame_sequence')
    need([c for c,n in cycles]==[1,2,3] and all(n>=3 for c,n in cycles),'present_cycle_incomplete')
    for c,n in cycles:
        actual=[r for r in sizes if r[0]==c]
        need(len(actual)==n and [r[3] for r in actual]==list(range(1,n+1)),'present_callback_count')
        need([(r[1],r[2]) for r in actual][-3:]==[(64,64),(96,80),(64,64)],'present_resize_callback')
        want=['device_swapchain','query']+['backbuffer','rtv','present','present']+['resize','backbuffer','rtv','present','present']*2
        need(operations[c]==want,'present_operations')
    need(set(modules)=={'d3d11.dll','dxgi.dll','winemetal.dll'},'present_modules')
    return dict(frames=18,cycles=3,modules=modules,ready=ready,callbacks=cycles)

def native(stderr,visible_sequences=()):
    validation(stderr)
    submit=re.findall(rb'^PEAR_PRESENT_SUBMIT sequence=(\d+) drawable=(\d+)\r?$',stderr,re.M)
    displays=re.findall(rb'^PEAR_PRESENT_DISPLAY sequence=(\d+) drawable=(\d+) time=([0-9.]+)\r?$',stderr,re.M)
    gpu=re.findall(rb'^PEAR_PRESENT_GPU sequence=(\d+) status=(\d+) error=(-?\d+)\r?$',stderr,re.M)
    need([int(s) for s,d in submit]==list(range(1,19)),'present_submit_count')
    need(len(displays)==18 and sorted(int(s) for s,d,t in displays)==list(range(1,19)),'present_display_incomplete')
    drawables={int(s):int(d) for s,d in submit}
    need(all(int(d)==drawables[int(s)] and (float(t)>0 or int(s) in visible_sequences) for s,d,t in displays),'present_display_identity')
    need(len(gpu)==18 and sorted(int(s) for s,v,e in gpu)==list(range(1,19)) and all(v==b'4' and e==b'0' for s,v,e in gpu),'present_gpu_incomplete')
    life=re.findall(rb'^PEAR_PRESENT_LIFE action=(create|destroy) kind=(\d+) number=(\d+)\r?$',stderr,re.M)
    live=set();created=[];destroyed=[]
    for op,k,n in life:
        key=(int(k),int(n))
        if op==b'create':need(key not in live and key not in created,'present_life_duplicate');live.add(key);created.append(key)
        else:need(key in live,'present_life_unowned');live.remove(key);destroyed.append(key)
    need(not live and sorted(created)==[(k,n) for k in range(3) for n in (1,2,3)] and sorted(destroyed)==sorted(created),'present_physical_teardown')
    registry=re.findall(rb'^PEAR_PRESENT_REGISTRY action=(acquire|release) status=(\d+) leases=(\d+) attachments=(\d+)\r?$',stderr,re.M)
    need(registry==[(op,b'0',count,count) for i in range(3) for op,count in [(b'acquire',b'1'),(b'release',b'0')]],'present_registry_teardown')
    windows=re.findall(rb'^PEAR_PRESENT_WINDOW window=(\d+) width=(\d+) height=(\d+) visible=1 title=1 main=1\r?$',stderr,re.M)
    need(len(windows)==18,'present_window_incomplete')
    need([(int(w),int(h)) for _,w,h in windows]==[(96 if p==1 else 64,80 if p==1 else 64) for c in range(3) for p in range(3) for f in range(2)],'present_native_size')
    pipelines=re.findall(rb'^PEAR_METAL_PIPELINE kind=render validation=(\d+) function=(\S+)\r?$',stderr,re.M)
    need(pipelines and all(v==b'1' for v,n in pipelines) and any(n==b'vs_present_quad' for v,n in pipelines),'present_pipeline_validation')
    return dict(presents=18,presented_callbacks=18,positive_presented_times=sum(float(t)>0 for _,_,t in displays),zero_presented_time_sequences=[int(s) for s,_,t in displays if float(t)==0],gpu_completed=18,physical_created=9,physical_destroyed=9,leases=0,attachments=0,window_ids=[int(row[0]) for row in windows])

def pixels(path):
    # Decode only the owned PNG using system ImageIO/CoreGraphics, never screen pixels.
    cf=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    cg=ctypes.CDLL('/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics')
    io=ctypes.CDLL('/System/Library/Frameworks/ImageIO.framework/ImageIO');P=ctypes.c_void_p;Z=ctypes.c_size_t;D=ctypes.c_double
    class Point(ctypes.Structure):_fields_=[('x',D),('y',D)]
    class Size(ctypes.Structure):_fields_=[('w',D),('h',D)]
    class Rect(ctypes.Structure):_fields_=[('origin',Point),('size',Size)]
    def function(lib,name,result,args):
        f=getattr(lib,name);f.restype=result;f.argtypes=args;return f
    urlf=function(cf,'CFURLCreateFromFileSystemRepresentation',P,[P,ctypes.c_char_p,ctypes.c_long,ctypes.c_bool]);release=function(cf,'CFRelease',None,[P])
    sourcef=function(io,'CGImageSourceCreateWithURL',P,[P,P]);imagef=function(io,'CGImageSourceCreateImageAtIndex',P,[P,Z,P])
    widthf=function(cg,'CGImageGetWidth',Z,[P]);heightf=function(cg,'CGImageGetHeight',Z,[P]);spacef=function(cg,'CGColorSpaceCreateDeviceRGB',P,[])
    contextf=function(cg,'CGBitmapContextCreate',P,[P,Z,Z,Z,Z,P,ctypes.c_uint]);draw=function(cg,'CGContextDrawImage',None,[P,Rect,P])
    owned=[]
    try:
        raw=str(path).encode();url=urlf(None,raw,len(raw),False);need(url,'present_image_url');owned.append(url)
        source=sourcef(url,None);need(source,'present_image_source');owned.append(source)
        image=imagef(source,0,None);need(image,'present_image_decode');owned.append(image)
        width,height=widthf(image),heightf(image);need(0<width<=512 and 0<height<=512,'present_image_size_bound')
        space=spacef();need(space,'present_image_space');owned.append(space)
        buffer=(ctypes.c_ubyte*(width*height*4))();ctx=contextf(buffer,width,height,8,width*4,space,0x4001);need(ctx,'present_image_context');owned.append(ctx)
        draw(ctx,Rect(Point(0,0),Size(width,height)),image);return width,height,bytes(buffer)
    finally:
        for p in reversed(owned):release(p)

def visible(run,ready,windows,capture_producer):
    v=read(run/'visible-captures.json');need(v['scope']=='owned_fixture_window_only','present_capture_scope')
    need(v['producer']==fact(capture_producer),'present_capture_producer')
    need(len(v['captures'])==9,'present_capture_incomplete');result=[]
    for i,(row,expected) in enumerate(zip(v['captures'],ready)):
        c,p,w,h=expected;need((row['cycle'],row['phase'],row['width'],row['height'])==expected and row['passed'],'present_capture_failed')
        need(row['native_window']['id']==windows[i*2] and row['native_window']['visible']==1 and row['native_window']['title_matches']==1,'present_capture_window')
        image=Path(row['image']['path']);need(image.parent==run and fact(image)==row['image'],'present_image_changed')
        need(row['argv']==['/usr/sbin/screencapture','-x','-o','-l'+str(windows[i*2]),'-t','png',str(image)] and row['exit_code']==0,'present_capture_command')
        iw,ih,data=pixels(image);need(iw%w==0 and ih%h==0 and iw//w==ih//h and iw//w in (1,2,3),'present_visible_size')
        color=([255,0,0],[0,255,0],[0,0,255])[p]
        matched=sum(all(abs(data[j+k]-color[k])<=3 for k in range(3)) and data[j+3]>=252 for j in range(0,len(data),4))
        need(matched>=iw*ih*0.95,'present_visible_color')
        result.append(dict(cycle=c,phase=p,width=iw,height=ih,matched_pixels=matched,image_sha256=row['image']['sha256']))
    return result

def visible_frames(run,windows,capture_producer):
    packet=read(run/'visible-frames.json')
    need(packet['scope']=='owned_fixture_individual_frames' and packet['producer']==fact(capture_producer),'present_frame_capture_producer')
    rows=packet['captures'];need(len(rows)==18,'present_frame_capture_count');result=[]
    for i,row in enumerate(rows):
        cycle,phase,frame=i//6+1,i%6//2,i%2;width,height=(96,80) if phase==1 else (64,64)
        need((row['cycle'],row['phase'],row['frame'],row['width'],row['height'])==(cycle,phase,frame,width,height) and row['passed'],'present_frame_capture_failed')
        native_window=row['native_window']
        need(native_window==dict(id=windows[i],width=width,height=height,visible=1,title_matches=1,main_thread=1),'present_frame_window')
        path=Path(row['image']['path']);need(path.parent==run and fact(path)==row['image'],'present_frame_image_changed')
        need(row['argv']==['/usr/sbin/screencapture','-x','-o','-l'+str(windows[i]),'-t','png',str(path)] and row['exit_code']==0,'present_frame_capture_command')
        iw,ih,data=pixels(path);need(iw%width==0 and ih%height==0 and iw//width==ih//height and iw//width in (1,2,3),'present_frame_visible_size')
        color=([255,0,0],[0,255,0],[0,0,255])[phase]
        if frame:color=[255-c for c in color]
        matched=sum(all(abs(data[j+k]-color[k])<=3 for k in range(3)) and data[j+3]>=252 for j in range(0,len(data),4))
        need(matched>=iw*ih*0.95,'present_frame_visible_color')
        result.append(dict(sequence=i+1,cycle=cycle,phase=phase,frame=frame,width=iw,height=ih,color=color,matched_pixels=matched,image_sha256=row['image']['sha256']))
    return result
