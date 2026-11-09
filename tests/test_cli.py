import os
import shutil
import tempfile
import unittest
import subprocess
import filecmp

from handwrite.sheettopng import ALL_CHARS


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.file_dir = os.path.dirname(os.path.abspath(__file__))
        self.temp_dir = tempfile.mkdtemp()
        self.sheets_dir = os.path.join(self.file_dir, "test_data", "sheettopng")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_single_input(self):
        # Check working with excellent input and no optional parameters
        subprocess.call(
            [
                "handwrite",
                os.path.join(self.file_dir, "test_data", "sheettopng", "excellent.jpg"),
                self.temp_dir,
            ]
        )
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "MyFont.ttf")))

    def test_single_input_with_optional_parameters(self):
        # Check working with optional parameters
        subprocess.call(
            [
                "handwrite",
                os.path.join(self.file_dir, "test_data", "sheettopng", "excellent.jpg"),
                self.temp_dir,
                "--directory",
                self.temp_dir,
                "--config",
                os.path.join(self.file_dir, "test_data", "config_data", "default.json"),
                "--filename",
                "CustomFont",
            ]
        )
        for i in ALL_CHARS:
            for suffix in [".bmp", ".png", ".svg"]:
                self.assertTrue(
                    os.path.exists(os.path.join(self.temp_dir, f"{i}", f"{i}{suffix}"))
                )
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "CustomFont.ttf")))

    def test_multiple_inputs(self):
        # Check working with multiple inputs
        try:
            subprocess.check_call(
                [
                    "handwrite",
                    self.sheets_dir,
                    self.temp_dir,
                ]
            )
        except subprocess.CalledProcessError as e:
            self.assertNotEqual(e.returncode, 0)

    def test_multiple_config(self):
        # Check working with multiple config files
        try:
            subprocess.check_call(
                [
                    "handwrite",
                    self.sheets_dir,
                    self.temp_dir,
                    "--config",
                    os.path.join(self.file_dir, "test_data", "config_data"),
                ]
            )
        except subprocess.CalledProcessError as e:
            self.assertNotEqual(e.returncode, 0)

    def test_font_filename_traversal(self):
        # POSIX and Windows style traversal must be neutralised to a basename
        marker = "pwn-%s" % os.path.basename(self.temp_dir)
        subprocess.call(
            [
                "handwrite",
                os.path.join(self.file_dir, "test_data", "sheettopng", "excellent.jpg"),
                self.temp_dir,
                "--filename",
                "../../../../tmp/" + marker,
            ]
        )
        escaped = os.path.abspath(
            os.path.join(self.temp_dir, "../../../../tmp", marker + ".ttf")
        )
        self.assertFalse(os.path.exists(escaped))
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, marker + ".ttf")))

        # Windows path form even on a POSIX host.
        win_marker = "winpwn-%s" % os.path.basename(self.temp_dir)
        subprocess.call(
            [
                "handwrite",
                os.path.join(self.file_dir, "test_data", "sheettopng", "excellent.jpg"),
                self.temp_dir,
                "--filename",
                "..\\..\\" + win_marker,
            ]
        )
        self.assertTrue(
            os.path.exists(os.path.join(self.temp_dir, win_marker + ".ttf"))
        )
        for name in os.listdir(self.temp_dir):
            self.assertNotIn("\\", name)

    def test_chinese_paths_and_filename(self):
        base = os.path.join(self.temp_dir, "测试目录")
        out_dir = os.path.join(base, "字体输出")
        keep_dir = os.path.join(base, "保留目录")
        subprocess.call(
            [
                "handwrite",
                os.path.join(self.file_dir, "test_data", "sheettopng", "excellent.jpg"),
                out_dir,
                "--directory",
                keep_dir,
                "--filename",
                "手写体",
            ]
        )
        self.assertTrue(os.path.exists(os.path.join(out_dir, "手写体.ttf")))
        # The retained directory keeps the normal intermediates.
        for codepoint in ("65", "90", "48"):
            for suffix in (".png", ".bmp", ".svg"):
                self.assertTrue(
                    os.path.exists(
                        os.path.join(keep_dir, codepoint, codepoint + suffix)
                    )
                )
