# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from pear_runtime.fixtures.inputs import fact,save
from pear_runtime.fixtures.controls.presentation import visible_frames
from pear_runtime.errors import Error

class VisibleFrames(unittest.TestCase):
    def packet(self,root):
        rows=[];decoded={};windows=[]
        for i in range(18):
            cycle,phase,frame=i//6+1,i%6//2,i%2;w,h=(96,80) if phase==1 else (64,64);window=100+cycle
            image=root/('frame-%d.png'%i);image.write_bytes(('owned-fixture-image-%d'%i).encode())
            color=([255,0,0],[0,255,0],[0,0,255])[phase]
            if frame:color=[255-c for c in color]
            decoded[str(image)]=(w,h,bytes(color+[255])*(w*h));windows.append(window)
            rows.append(dict(cycle=cycle,phase=phase,frame=frame,width=w,height=h,passed=True,
                native_window=dict(id=window,width=w,height=h,visible=1,title_matches=1,main_thread=1),
                image=fact(image),exit_code=0,argv=['/usr/sbin/screencapture','-x','-o','-l'+str(window),'-t','png',str(image)]))
        packet=dict(scope='owned_fixture_individual_frames',captures=rows,producer=fact(Path(__file__)))
        save(root/'visible-frames.json',packet)
        return packet,decoded,windows
    def test_every_alternating_frame_observed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();_,decoded,windows=self.packet(root)
            with patch('pear_runtime.fixtures.controls.presentation.pixels',side_effect=lambda p:decoded[str(p)]):
                result=visible_frames(root,windows,Path(__file__))
            self.assertEqual([r['sequence'] for r in result],list(range(1,19)))
    def test_previous_frame_cannot_prove_next_frame(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();p,decoded,windows=self.packet(root)
            decoded[p['captures'][1]['image']['path']]=decoded[p['captures'][0]['image']['path']]
            with patch('pear_runtime.fixtures.controls.presentation.pixels',side_effect=lambda p:decoded[str(p)]),self.assertRaises(Error):visible_frames(root,windows,Path(__file__))
    def test_missing_frame_cannot_be_a_phase_capture_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();p,decoded,windows=self.packet(root);p['captures'].pop();save(root/'visible-frames.json',p)
            with self.assertRaises(Error):visible_frames(root,windows,Path(__file__))
if __name__=='__main__':unittest.main()
