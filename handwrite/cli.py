import os
import json
import shutil
import argparse

from handwrite import SHEETtoPNG
from handwrite import PNGtoSVG
from handwrite import SVGtoTTF
from handwrite import security


def run(sheet, output_directory, characters_dir, config, metadata):
    converters(sheet, output_directory, characters_dir, config, metadata)


def _validated_directory(path):
    if os.path.exists(path) and not os.path.isdir(path):
        raise NotADirectoryError("%s is not a directory." % path)
    os.makedirs(path, exist_ok=True)
    return os.path.abspath(path)


def _sheet_staging_name(sheet_path):
    extension = os.path.splitext(sheet_path)[1].lower()
    if len(extension) <= 8 and all(char.isalnum() or char == "." for char in extension):
        return "sheet" + extension
    return "sheet"


def converters(sheet, output_directory, directory=None, config=None, metadata=None):
    """Run the three converters under one explicit file access plan.

    1. Explicit inputs (sheet, config) and metadata are validated once and
       snapshotted into a private working directory, so swapping them after
       validation cannot change what is processed.
    2. SHEETtoPNG, PNGtoSVG and FontForge operate only on files inside that
       private, link-free snapshot; only the current run's codepoints are
       converted.
    3. Intermediates are published back to the retained ``--directory`` and
       the TTF into the output directory through no-follow operations, so
       symbolic links in those directories cannot escape their boundary.
    """
    if config is None:
        config = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "default.json"
        )
    if os.path.isdir(config):
        raise IsADirectoryError("Config parameter should not be a directory.")
    if os.path.isdir(sheet):
        raise IsADirectoryError("Sheet parameter should not be a directory.")

    outdir = _validated_directory(output_directory)
    preserve = _validated_directory(directory) if directory else None
    metadata = security.validate_metadata(metadata)

    # Validate + snapshot the explicit inputs before any converter runs.
    config_bytes = security.read_input_file(config)
    config_data = security.load_config(config_bytes)
    sheet_bytes = security.read_input_file(sheet)

    workdir = security.private_workdir()
    try:
        staged_config = security.write_private(
            workdir, "config.json", json.dumps(config_data).encode("utf-8")
        )
        staged_sheet = security.write_private(
            workdir, _sheet_staging_name(sheet), sheet_bytes
        )
        characters_dir = os.path.join(workdir, "characters")
        os.mkdir(characters_dir)

        # Image conversion happens entirely inside the private snapshot.
        SHEETtoPNG().convert(staged_sheet, characters_dir, staged_config)
        codepoints = security.planned_codepoints(characters_dir)
        PNGtoSVG().convert(characters_dir, codepoints=codepoints)

        # Publish the retained intermediates, then build the font from the
        # snapshot and publish the TTF safely into the output directory.
        if preserve is not None:
            security.publish_characters(
                characters_dir,
                preserve,
                codepoints,
                suffixes=(".png", ".bmp", ".svg"),
            )
        SVGtoTTF().convert(characters_dir, outdir, staged_config, metadata)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_path", help="Path to sample sheet")
    parser.add_argument("output_directory", help="Directory Path to save font output")
    parser.add_argument(
        "--directory",
        help="Generate additional files to this path (Temp by default)",
        default=None,
    )
    parser.add_argument("--config", help="Use custom configuration file", default=None)
    parser.add_argument("--filename", help="Font File name", default=None)
    parser.add_argument("--family", help="Font Family name", default=None)
    parser.add_argument("--style", help="Font Style name", default=None)

    args = parser.parse_args()
    metadata = {"filename": args.filename, "family": args.family, "style": args.style}
    converters(
        args.input_path, args.output_directory, args.directory, args.config, metadata
    )
