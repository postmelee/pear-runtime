# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original bounded capture of the declared fixture-owned window only."""
import re
import subprocess
from pear_runtime.fixtures.inputs import fact, save

class Capture:
    def __init__(self,output):
        self.output=output;self.rows=[];self.seen=set()
    def poll(self,stdout,stderr):
        ready=re.findall(rb'^PEAR_PRESENT_READY cycle=(\d+) phase=(\d+) width=(\d+) height=(\d+)\r?$',stdout,re.M)
        windows=re.findall(rb'^PEAR_PRESENT_WINDOW window=(\d+) width=(\d+) height=(\d+) visible=(\d+) title=(\d+) main=(\d+)\r?$',stderr,re.M)
        for fields in ready:
            cycle,phase,width,height=map(int,fields);key=(cycle,phase)
            if key in self.seen:continue
            self.seen.add(key)
            row=dict(cycle=cycle,phase=phase,width=width,height=height,passed=False)
            self.rows.append(row)
            if not windows:row['error']='owned_window_unobserved';continue
            window,w,h,visible,title,main=map(int,windows[-1])
            row['native_window']=dict(id=window,width=w,height=h,visible=visible,title_matches=title,main_thread=main)
            if (w,h,visible,title,main)!=(width,height,1,1,1):row['error']='owned_window_mismatch';continue
            path=self.output/('visible-%d-%d.png'%key)
            args=['/usr/sbin/screencapture','-x','-o','-l'+str(window),'-t','png',str(path)]
            try:
                p=subprocess.run(args,capture_output=True,timeout=3)
                row.update(argv=args,exit_code=p.returncode,stderr=p.stderr.decode(errors='replace'))
                if p.returncode==0 and path.is_file():row.update(passed=True,image=fact(path))
            except subprocess.TimeoutExpired:row['error']='capture_timeout'
        save(self.output/'visible-captures.json',dict(scope='owned_fixture_window_only',captures=self.rows,producer=fact(__file__)))


class FrameCapture:
    """Each expected frame has a distinct color and remains visible for 1.5s."""
    def __init__(self,output):self.output=output;self.rows=[];self.seen=set()
    def poll(self,stdout,stderr):
        frames=re.findall(rb'^PEAR_PRESENT_FRAME cycle=(\d+) phase=(\d+) frame=(\d+) width=(\d+) height=(\d+) gpu=1\r?$',stdout,re.M)
        windows=re.findall(rb'^PEAR_PRESENT_WINDOW window=(\d+) width=(\d+) height=(\d+) visible=(\d+) title=(\d+) main=(\d+)\r?$',stderr,re.M)
        for fields in frames:
            cycle,phase,frame,width,height=map(int,fields);key=(cycle,phase,frame)
            if key in self.seen:continue
            self.seen.add(key);row=dict(cycle=cycle,phase=phase,frame=frame,width=width,height=height,passed=False);self.rows.append(row)
            index=(cycle-1)*6+phase*2+frame
            if len(windows)<=index:row['error']='owned_frame_window_unobserved';continue
            window,w,h,visible,title,main=map(int,windows[index]);row['native_window']=dict(id=window,width=w,height=h,visible=visible,title_matches=title,main_thread=main)
            if (w,h,visible,title,main)!=(width,height,1,1,1):row['error']='owned_frame_window_mismatch';continue
            path=self.output/('frame-%d-%d-%d.png'%key);args=['/usr/sbin/screencapture','-x','-o','-l'+str(window),'-t','png',str(path)]
            try:
                p=subprocess.run(args,capture_output=True,timeout=3);row.update(argv=args,exit_code=p.returncode,stderr=p.stderr.decode(errors='replace'))
                if p.returncode==0 and path.is_file():row.update(passed=True,image=fact(path))
            except subprocess.TimeoutExpired:row['error']='capture_timeout'
        save(self.output/'visible-frames.json',dict(scope='owned_fixture_individual_frames',captures=self.rows,producer=fact(__file__)))
