# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
import unittest

class PresentationTests(unittest.TestCase):
    def observations(self):
        rows=[]
        for cycle in range(3):
            for kind in range(3):rows.append(f'PEAR_PRESENT_LIFE action=create kind={kind} number={cycle+1}')
            rows.append('PEAR_PRESENT_REGISTRY action=acquire status=0 leases=1 attachments=1')
            for phase in range(3):
                w,h=(96,80) if phase==1 else (64,64)
                for frame in range(2):
                    sequence=cycle*6+phase*2+frame+1
                    rows.extend([f'PEAR_PRESENT_WINDOW window={100+cycle} width={w} height={h} visible=1 title=1 main=1',
                        f'PEAR_PRESENT_SUBMIT sequence={sequence} drawable={sequence}',
                        f'PEAR_PRESENT_DISPLAY sequence={sequence} drawable={sequence} time=123.01',
                        f'PEAR_PRESENT_GPU sequence={sequence} status=4 error=0'])
            rows.append('PEAR_PRESENT_REGISTRY action=release status=0 leases=0 attachments=0')
            for kind in range(3):rows.append(f'PEAR_PRESENT_LIFE action=destroy kind={kind} number={cycle+1}')
        rows.append('PEAR_METAL_PIPELINE kind=render validation=1 function=vs_present_quad')
        return ('\n'.join(rows)+'\n').encode()

    def test_complete_native_presentation(self):
        from pear_runtime.fixtures.controls.presentation import native
        self.assertEqual(native(self.observations())['presented_callbacks'],18)

    def test_gpu_completion_does_not_replace_display(self):
        from pear_runtime.fixtures.controls.presentation import native
        raw=self.observations()
        raw=b'\n'.join(line for line in raw.splitlines() if not line.startswith(b'PEAR_PRESENT_DISPLAY sequence=18 '))+b'\n'
        with self.assertRaises(Exception):native(raw)

    def test_wrong_drawable_or_zero_presented_time(self):
        from pear_runtime.fixtures.controls.presentation import native
        for old,new in [(b'DISPLAY sequence=1 drawable=1 ',b'DISPLAY sequence=1 drawable=999 '),(b'time=123.01',b'time=0.00')]:
            with self.subTest(new=new),self.assertRaises(Exception):native(self.observations().replace(old,new))

    def test_failed_gpu_work_is_not_completion(self):
        from pear_runtime.fixtures.controls.presentation import native
        with self.assertRaises(Exception):native(self.observations().replace(b'status=4 error=0',b'status=5 error=8',1))

    def test_com_release_cannot_replace_physical_destruction(self):
        from pear_runtime.fixtures.controls.presentation import native
        for row in (b'PEAR_PRESENT_LIFE action=destroy kind=1 number=3\n',b'PEAR_PRESENT_LIFE action=destroy kind=2 number=3\n'):
            with self.subTest(row=row),self.assertRaises(Exception):native(self.observations().replace(row,b''))

    def test_pending_attachment_or_unseen_window_fails(self):
        from pear_runtime.fixtures.controls.presentation import native
        for old,new in [(b'leases=0 attachments=0',b'leases=0 attachments=1'),(b'visible=1',b'visible=0')]:
            with self.subTest(new=new),self.assertRaises(Exception):native(self.observations().replace(old,new))
