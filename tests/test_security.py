import json
import os
import shutil
import stat
import tempfile
import threading
import unittest

from handwrite import security
from handwrite.pngtosvg import PNGtoSVG
from handwrite.sheettopng import SHEETtoPNG

TEST_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")
SHEET = os.path.join(TEST_DATA, "sheettopng", "excellent.jpg")
CONFIG = os.path.join(TEST_DATA, "config_data", "default.json")
SAMPLE_PNG = os.path.join(TEST_DATA, "pngtosvg", "34", "34.png")


def make_sentinel(directory, name="sentinel"):
    """Create a file outside the attacked directory; returns its path."""
    path = os.path.join(directory, name)
    with open(path, "w") as handle:
        handle.write("SENTINEL")
    return path


def sentinel_intact(path):
    with open(path) as handle:
        return handle.read() == "SENTINEL"


class TestFontFilenameSanitizer(unittest.TestCase):
    def assertSafeBasename(self, raw):
        result = security.sanitize_font_filename(raw)
        self.assertNotIn("/", result)
        self.assertNotIn("\\", result)
        self.assertNotIn(":", result)
        self.assertNotIn("..", result)
        return result

    def test_posix_traversal(self):
        for raw, expected in (
            ("../../evil", "evil"),
            ("../evil", "evil"),
            ("/etc/passwd", "passwd"),
            ("a/../../../evil.ttf", "evil.ttf"),
        ):
            self.assertEqual(self.assertSafeBasename(raw), expected)

    def test_windows_path_forms(self):
        self.assertEqual(self.assertSafeBasename("..\\..\\evil"), "evil")
        self.assertEqual(self.assertSafeBasename("C:\\Windows\\evil.ttf"), "evil.ttf")
        self.assertEqual(self.assertSafeBasename("C:evil"), "evil")
        self.assertEqual(self.assertSafeBasename("D:/fonts/evil"), "evil")
        self.assertEqual(self.assertSafeBasename("evil:stream.ttf"), "stream.ttf")

    def test_illegal_names_rejected(self):
        for raw in ("", ".", "..", "...", "  . ", "a\x00b", "a\nb"):
            with self.assertRaises(security.PathSecurityError):
                security.sanitize_font_filename(raw)

    def test_unicode_names_preserved(self):
        self.assertEqual(security.sanitize_font_filename("手写体"), "手写体")
        self.assertEqual(security.sanitize_font_filename("My Font.ttf"), "My Font.ttf")


class TestFontPathPlanning(unittest.TestCase):
    def setUp(self):
        self.outdir = os.path.realpath(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.outdir)

    def test_traversal_stays_inside(self):
        for raw in ("../../pwn", "..\\..\\pwn", "/abs/pwn", "C:/pwn"):
            path = security.resolve_font_path(self.outdir, raw)
            self.assertEqual(os.path.commonpath((self.outdir, path)), self.outdir)

    def test_numbering_quirk(self):
        open(os.path.join(self.outdir, "MyFont.ttf"), "w").close()
        first = security.resolve_font_path(self.outdir, "MyFont")
        self.assertTrue(first.endswith("MyFont (1).ttf"))
        # Second run starts numbering over from the base name again.
        open(first, "w").close()
        second = security.resolve_font_path(self.outdir, "MyFont")
        self.assertTrue(second.endswith("MyFont (1) (1).ttf"))

    def test_existing_ttf_name_numbering(self):
        open(os.path.join(self.outdir, "MyFont.ttf"), "w").close()
        self.assertTrue(
            security.resolve_font_path(self.outdir, "MyFont.ttf").endswith(
                "MyFont (1).ttf"
            )
        )


class TestSafeFontPublish(unittest.TestCase):
    def setUp(self):
        self.outdir = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()
        self.staged = os.path.join(tempfile.mkdtemp(), "font.ttf")
        with open(self.staged, "w") as handle:
            handle.write("FONT")

    def tearDown(self):
        for directory in (self.outdir, self.outside, os.path.dirname(self.staged)):
            shutil.rmtree(directory, ignore_errors=True)

    def test_prefixed_link_replaced_not_followed(self):
        sentinel = make_sentinel(self.outside)
        os.symlink(sentinel, os.path.join(self.outdir, "MyFont.ttf"))
        result = security.publish_font(self.staged, self.outdir, "MyFont")
        self.assertTrue(stat.S_ISREG(os.lstat(result).st_mode))
        self.assertFalse(os.path.islink(result))
        # Link target outside the directory is untouched.
        self.assertTrue(sentinel_intact(sentinel))
        with open(result) as handle:
            self.assertEqual(handle.read(), "FONT")

    def test_dangling_link_does_not_create_target(self):
        dangling_target = os.path.join(self.outside, "never")
        os.symlink(dangling_target, os.path.join(self.outdir, "MyFont.ttf"))
        security.publish_font(self.staged, self.outdir, "MyFont")
        self.assertFalse(os.path.exists(dangling_target))
        self.assertTrue(
            stat.S_ISREG(os.lstat(os.path.join(self.outdir, "MyFont.ttf")).st_mode)
        )

    def test_traversal_name_published_inside(self):
        result = security.publish_font(
            self.staged, self.outdir, "../../%s-evil" % os.path.basename(self.outside)
        )
        self.assertEqual(
            os.path.dirname(os.path.realpath(result)), os.path.realpath(self.outdir)
        )
        self.assertEqual(os.listdir(self.outside), [])


class TestNoFollowPublisher(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_symlinked_file_blocks_write(self):
        sentinel = make_sentinel(self.outside)
        os.symlink(sentinel, os.path.join(self.root, "65.bmp"))
        with security.root_directory(self.root) as root:
            with self.assertRaises(security.PathSecurityError):
                security.publish_bytes(root, "65.bmp", b"data")
        self.assertTrue(sentinel_intact(sentinel))

    def test_symlinked_directory_refused(self):
        target = tempfile.mkdtemp(dir=self.outside)
        os.symlink(target, os.path.join(self.root, "65"))
        with security.root_directory(self.root) as root:
            with self.assertRaises(security.PathSecurityError):
                with security.child_directory(root, "65", create=True):
                    self.fail("symlinked directory should not be entered")
        self.assertEqual(os.listdir(target), [])

    def test_regular_overwrite_and_creation(self):
        with security.root_directory(self.root) as root:
            with security.child_directory(root, "65", create=True) as char_dir:
                security.publish_bytes(char_dir, "65.png", b"one")
                security.publish_bytes(char_dir, "65.png", b"two")
        with open(os.path.join(self.root, "65", "65.png"), "rb") as handle:
            self.assertEqual(handle.read(), b"two")

    def test_verify_planned_file(self):
        os.mkdir(os.path.join(self.root, "65"))
        svg = os.path.join(self.root, "65", "65.svg")
        with open(svg, "w") as handle:
            handle.write("<svg/>")
        self.assertEqual(
            os.path.realpath(security.verify_planned_file(self.root, "65", "65.svg")),
            os.path.realpath(svg),
        )
        # Symlinked SVG is rejected.
        sentinel = make_sentinel(self.outside, "font-sentinel")
        os.mkdir(os.path.join(self.root, "66"))
        os.symlink(sentinel, os.path.join(self.root, "66", "66.svg"))
        with self.assertRaises(security.PathSecurityError):
            security.verify_planned_file(self.root, "66", "66.svg")
        self.assertTrue(sentinel_intact(sentinel))


class TestInputSnapshot(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp)

    def test_directory_input_rejected(self):
        with self.assertRaises(IsADirectoryError):
            security.read_input_file(self.temp)

    def test_bytes_pinned_when_path_swapped_after_open_plan(self):
        # The CLI relies on snapshot bytes: replacing the file after the
        # snapshot must not affect what converters receive.
        path = os.path.join(self.temp, "config.json")
        with open(path, "w") as handle:
            handle.write(json.dumps({"glyphs": [65]}))
        data = security.read_input_file(path)
        with open(path, "w") as handle:
            handle.write("{not json anymore}")
        config = security.load_config(data)
        self.assertEqual(config["glyphs"], [65])


class TestValidation(unittest.TestCase):
    def test_codepoints(self):
        security.validate_codepoints([0, 65, 0x10FFFF])
        for bad in ([[65.0]], [["A"]], [[True]], [[-1]], [[0x110000]]):
            with self.assertRaises(security.PathSecurityError):
                security.validate_codepoints(bad[0])

    def test_config(self):
        security.validate_config({"glyphs": [65], "props": {}})
        with self.assertRaises(security.PathSecurityError):
            security.validate_config({"glyphs": "nope"})
        with self.assertRaises(security.PathSecurityError):
            security.load_config(b"not json")

    def test_metadata(self):
        self.assertEqual(
            security.validate_metadata({"filename": "字体"}),
            {"filename": "字体", "family": None, "style": None},
        )
        for bad in (
            {"filename": 123},
            {"family": "x\x00y"},
            "not-a-dict",
        ):
            with self.assertRaises(security.PathSecurityError):
                security.validate_metadata(bad)


class TestPNGtoSVGLinkAttacks(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()
        self.characters = os.path.join(self.work, "characters")
        os.mkdir(self.characters)
        self.converter = PNGtoSVG()

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def _place_png(self, codepoint):
        directory = os.path.join(self.characters, str(codepoint))
        os.mkdir(directory)
        target = os.path.join(directory, "%d.png" % codepoint)
        shutil.copyfile(SAMPLE_PNG, target)
        return directory, target

    def test_bmp_symlink_blocks_conversion(self):
        directory, _ = self._place_png(65)
        sentinel = make_sentinel(self.outside, "bmp-target")
        os.symlink(sentinel, os.path.join(directory, "65.bmp"))
        with self.assertRaises(security.PathSecurityError):
            self.converter.convert(self.characters, codepoints=[65])
        self.assertTrue(sentinel_intact(sentinel))

    def test_svg_symlink_blocks_conversion(self):
        directory, _ = self._place_png(65)
        sentinel = make_sentinel(self.outside, "svg-target")
        os.symlink(sentinel, os.path.join(directory, "65.svg"))
        with self.assertRaises(security.PathSecurityError):
            self.converter.convert(self.characters, codepoints=[65])
        self.assertTrue(sentinel_intact(sentinel))

    def test_source_png_symlink_refused(self):
        directory, _ = self._place_png(66)
        os.unlink(os.path.join(directory, "66.png"))
        external = os.path.join(self.outside, "external.png")
        shutil.copyfile(SAMPLE_PNG, external)
        os.symlink(external, os.path.join(directory, "66.png"))
        with self.assertRaises(security.PathSecurityError):
            self.converter.convert(self.characters, codepoints=[66])
        self.assertFalse(os.path.exists(os.path.join(directory, "66.bmp")))
        self.assertFalse(os.path.exists(os.path.join(directory, "66.svg")))

    def test_unplanned_codepoint_skipped(self):
        directory, _ = self._place_png(999)
        self.converter.convert(self.characters, codepoints=[65])
        self.assertFalse(os.path.exists(os.path.join(directory, "999.bmp")))
        self.assertFalse(os.path.exists(os.path.join(directory, "999.svg")))

    def test_normal_conversion(self):
        directory, _ = self._place_png(65)
        self.converter.convert(self.characters, codepoints=[65])
        for suffix in (".png", ".bmp", ".svg"):
            path = os.path.join(directory, "65" + suffix)
            self.assertTrue(stat.S_ISREG(os.lstat(path).st_mode), path)
            self.assertFalse(os.path.islink(path))


class TestSHEETtoPNGLinkAttacks(unittest.TestCase):
    def setUp(self):
        self.characters = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.characters, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_codepoint_directory_symlink_refused(self):
        outside_target = os.path.join(self.outside, "65")
        os.mkdir(outside_target)
        os.symlink(outside_target, os.path.join(self.characters, "65"))
        with self.assertRaises(security.PathSecurityError):
            SHEETtoPNG().convert(SHEET, self.characters, CONFIG)
        self.assertEqual(os.listdir(outside_target), [])


class TestPreserveDirectoryLinkAttacks(unittest.TestCase):
    """Links waiting inside a reused keep dir must fail publication."""

    def setUp(self):
        self.characters = tempfile.mkdtemp()
        self.preserve = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()
        os.mkdir(os.path.join(self.characters, "65"))
        for suffix in (".png", ".bmp", ".svg"):
            with open(
                os.path.join(self.characters, "65", "65" + suffix), "w"
            ) as handle:
                handle.write("x")

    def tearDown(self):
        for directory in (self.characters, self.preserve, self.outside):
            shutil.rmtree(directory, ignore_errors=True)

    def test_prefixed_png_link_in_keep_dir(self):
        sentinel = make_sentinel(self.outside, "png-target")
        os.mkdir(os.path.join(self.preserve, "65"))
        os.symlink(sentinel, os.path.join(self.preserve, "65", "65.png"))
        with self.assertRaises(security.PathSecurityError):
            security.publish_characters(
                self.characters,
                self.preserve,
                [65],
                suffixes=(".png", ".bmp", ".svg"),
            )
        self.assertTrue(sentinel_intact(sentinel))

    def test_prefixed_bmp_link_in_keep_dir(self):
        sentinel = make_sentinel(self.outside, "bmp-target")
        os.mkdir(os.path.join(self.preserve, "65"))
        os.symlink(sentinel, os.path.join(self.preserve, "65", "65.bmp"))
        with self.assertRaises(security.PathSecurityError):
            security.publish_characters(
                self.characters,
                self.preserve,
                [65],
                suffixes=(".png", ".bmp", ".svg"),
            )
        self.assertTrue(sentinel_intact(sentinel))
        # The PNG published before the link was hit is a regular file.
        published = os.path.join(self.preserve, "65", "65.png")
        self.assertTrue(stat.S_ISREG(os.lstat(published).st_mode))


class TestConfigSwapAfterValidation(unittest.TestCase):
    """Swapping the config file after validation must not reach converters."""

    def setUp(self):
        self.temp = tempfile.mkdtemp()
        self.outdir = os.path.join(self.temp, "out")
        self.preserve = os.path.join(self.temp, "keep")
        os.mkdir(self.outdir)
        os.mkdir(self.preserve)
        self.config = os.path.join(self.temp, "config.json")
        shutil.copyfile(CONFIG, self.config)

    def tearDown(self):
        shutil.rmtree(self.temp, ignore_errors=True)

    def test_swap_mid_run_uses_snapshot(self):
        from handwrite.cli import converters

        def swap():
            # Replace the validated config while conversion is in progress.
            with open(self.config, "w") as handle:
                handle.write("{broken json")

        timer = threading.Timer(0.3, swap)
        timer.start()
        try:
            converters(
                SHEET,
                self.outdir,
                self.preserve,
                self.config,
                {"filename": "SnapFont"},
            )
        finally:
            timer.join()
        self.assertTrue(os.path.exists(os.path.join(self.outdir, "SnapFont.ttf")))


if __name__ == "__main__":
    unittest.main()
