import contextlib
import io
import os
import shutil
import stat
import subprocess
import tempfile

from PIL import Image, ImageChops

from handwrite import security


class PotraceNotFound(Exception):
    pass


class PNGtoSVG:
    """Converter class to convert character PNGs to BMPs and SVGs."""

    def convert(self, directory, codepoints=None):
        """Convert planned .png files in the directory to .bmp and .svg.

        Only files named ``<codepoint>.png`` (decimal Unicode value) that
        belong to this run's codepoints are processed. Symbolic links are
        never followed: every conversion happens in a private staging
        directory, and the resulting .bmp/.svg are published back next to
        the source without traversing links.

        Parameters
        ----------
        directory : str
            Directory containing the character images.
        codepoints : iterable of int, optional
            Codepoints allowed for this run. When ``None`` every valid
            decimal named ``<codepoint>.png`` is accepted (standalone use).
        """
        allowed = None
        if codepoints is not None:
            allowed = set()
            for codepoint in codepoints:
                if not security.is_codepoint(codepoint):
                    raise security.PathSecurityError(
                        "Invalid codepoint in conversion plan: %r" % (codepoint,)
                    )
                allowed.add(codepoint)

        staging = security.private_workdir()
        try:
            for index, (source, rel_dir, name) in enumerate(
                self._discover_pngs(directory, allowed)
            ):
                stem = name[:-4]
                stage_png = os.path.join(staging, "%s.png" % index)
                with open(stage_png, "wb") as handle:
                    handle.write(security.read_planned_file(source))
                self.pngToBmp(stage_png)
                self.bmpToSvg(os.path.join(staging, "%s.bmp" % index))
                # Publish only after both derivatives exist in staging.
                with security.root_directory(directory) as root:
                    with _descend(root, rel_dir) as target:
                        security.publish_file(
                            os.path.join(staging, "%s.bmp" % index),
                            target,
                            stem + ".bmp",
                        )
                        security.publish_file(
                            os.path.join(staging, "%s.svg" % index),
                            target,
                            stem + ".svg",
                        )
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _discover_pngs(self, directory, allowed):
        """Yield (path, rel_dir_components, filename) for planned PNGs."""
        directory = os.path.abspath(directory)
        for current_root, dirs, files in os.walk(directory, followlinks=False):
            dirs.sort()
            files.sort()
            rel = os.path.relpath(current_root, directory)
            rel_dir = () if rel == "." else tuple(rel.split(os.sep))
            for filename in files:
                if not filename.endswith(".png"):
                    continue
                stem = filename[:-4]
                if not stem or any(not ("0" <= char <= "9") for char in stem):
                    continue
                codepoint = int(stem)
                if not security.is_codepoint(codepoint):
                    continue
                if allowed is not None and codepoint not in allowed:
                    continue
                path = os.path.join(current_root, filename)
                mode = os.lstat(path).st_mode
                if stat.S_ISLNK(mode):
                    raise security.PathSecurityError(
                        "Refusing to read symbolic link: %s" % path
                    )
                if not stat.S_ISREG(mode):
                    raise security.PathSecurityError("Not a regular file: %s" % path)
                yield path, rel_dir, filename

    def bmpToSvg(self, path):
        """Convert .bmp image to .svg using potrace.

        Potrace runs on a private copy of the BMP and the SVG is written
        next to the source without following symbolic links, so a
        pre-planted ``<name>.svg`` link cannot be overwritten.

        Parameters
        ----------
        path : str
            Path to the bmp file to be converted.

        Raises
        ------
        PotraceNotFound
            Raised if potrace not found in path by shutil.which()
        """
        if shutil.which("potrace") is None:
            raise PotraceNotFound("Potrace is either not installed or not in path")

        output = path[0:-4] + ".svg"
        staging = tempfile.mkdtemp(prefix="handwrite-potrace-")
        try:
            stage_bmp = os.path.join(staging, "input.bmp")
            with open(stage_bmp, "wb") as handle:
                handle.write(security.read_planned_file(path))
            stage_svg = os.path.join(staging, "output.svg")
            subprocess.run(
                ["potrace", stage_bmp, "-b", "svg", "-o", stage_svg], check=True
            )
            directory, basename = os.path.split(output)
            with security.root_directory(directory) as root:
                security.publish_file(stage_svg, root, basename)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def pngToBmp(self, path):
        """Convert .png image to .bmp.

        The source PNG is read without following symbolic links and the
        resulting BMP is written next to it through a no-follow create, so
        a pre-planted ``<name>.bmp`` link cannot be overwritten.

        Parameters
        ----------
        path : str
            Path to the png file to be converted.
        """
        img = Image.open(io.BytesIO(security.read_planned_file(path)))
        img = img.convert("RGBA").resize((100, 100))

        # Threshold image to convert each pixel to either black or white
        threshold = 200
        data = []
        for pix in img.get_flattened_data():
            if pix[0] >= threshold and pix[1] >= threshold and pix[3] >= threshold:
                data.append((255, 255, 255, 0))
            else:
                data.append((0, 0, 0, 1))
        img.putdata(data)

        output = path[0:-4] + ".bmp"
        directory, basename = os.path.split(output)
        buffer = io.BytesIO()
        img.save(buffer, format="BMP")
        with security.root_directory(directory) as root:
            security.publish_bytes(root, basename, buffer.getvalue())

    def trim(self, im_path):
        im = Image.open(io.BytesIO(security.read_planned_file(im_path)))
        bg = Image.new(im.mode, im.size, im.getpixel((0, 0)))
        diff = ImageChops.difference(im, bg)
        bbox = list(diff.getbbox())
        bbox[0] -= 1
        bbox[1] -= 1
        bbox[2] += 1
        bbox[3] += 1
        cropped_im = im.crop(bbox)
        directory, basename = os.path.split(im_path)
        buffer = io.BytesIO()
        cropped_im.save(buffer, format=os.path.splitext(basename)[1].lstrip("."))
        with security.root_directory(directory) as root:
            security.publish_bytes(root, basename, buffer.getvalue())


@contextlib.contextmanager
def _descend(root, components):
    """Descend from a held directory token through real subdirectories."""
    with contextlib.ExitStack() as stack:
        token = root
        for component in components:
            token = stack.enter_context(
                security.child_directory(token, component, create=False)
            )
        yield token
