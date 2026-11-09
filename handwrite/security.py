"""Filesystem access boundary for the handwrite conversion pipeline.

The pipeline is only allowed to touch three classes of paths:

1. Explicit user inputs (the sample sheet and the config file). They are
   validated once and snapshotted immediately: the bytes are read through
   the already opened file descriptor, so replacing the path (a symlink
   swap or an overwrite) *after* validation cannot change what the
   converters see.
2. Derivatives (PNG/BMP/SVG/TTF). They are produced exclusively inside a
   private ``0700`` working directory that nobody else can plant links in.
   Retained directories (``--directory``) are never read from.
3. Published artefacts. They are moved into the user chosen directories
   through held directory descriptors and ``openat``/``O_NOFOLLOW`` so a
   pre-planted symbolic link can never redirect a read or a write outside
   that directory. A directory swapped after validation is caught by the
   kernel because writes go through a descriptor held on the original
   directory inode.

The font file name is reduced to a plain basename (neutralising both POSIX
and Windows path forms) before publication while preserving the historical
``"name (1).ttf"`` collision numbering.
"""

import contextlib
import errno
import json
import os
import stat
import tempfile

MAX_CODEPOINT = 0x10FFFF

# POSIX gives us directory descriptors + openat(O_NOFOLLOW); on platforms
# without them (Windows) we fall back to lstat guarded path operations.
_HAS_OPENAT = hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")


class PathSecurityError(ValueError):
    """A path would escape the planned filesystem boundary."""


# ---------------------------------------------------------------------------
# Codepoint / config / metadata validation
# ---------------------------------------------------------------------------


def is_codepoint(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_CODEPOINT
    )


def validate_codepoints(values):
    if not isinstance(values, (list, tuple)):
        raise PathSecurityError("'glyphs' must be a list of codepoints.")
    for value in values:
        if not is_codepoint(value):
            raise PathSecurityError("Invalid codepoint in config: %r" % (value,))
    return values


def validate_config(config):
    if not isinstance(config, dict):
        raise PathSecurityError("Config must be a JSON object.")
    if "glyphs" in config and config["glyphs"] is not None:
        validate_codepoints(config["glyphs"])
    for key in ("props", "sfnt_names", "typography_parameters"):
        if (
            key in config
            and config[key] is not None
            and not isinstance(config[key], dict)
        ):
            raise PathSecurityError("Config section %r must be an object." % key)
    threshold = config.get("threshold_value")
    if threshold is not None and (
        isinstance(threshold, bool) or not isinstance(threshold, (int, float))
    ):
        raise PathSecurityError("'threshold_value' must be a number.")
    return config


def load_config(data):
    """Parse and validate config bytes/str once, before any conversion."""
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        config = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PathSecurityError("Could not parse config file: %s" % error) from error
    return validate_config(config)


def validate_metadata(metadata):
    if metadata is None:
        return {"filename": None, "family": None, "style": None}
    if not isinstance(metadata, dict):
        raise PathSecurityError("Metadata must be an object.")
    result = {}
    for key in ("filename", "family", "style"):
        value = metadata.get(key)
        if value is None:
            result[key] = None
        elif isinstance(value, str):
            if len(value) > 256 or any(ord(char) < 32 for char in value):
                raise PathSecurityError(
                    "Metadata value %r contains illegal characters." % key
                )
            result[key] = value
        else:
            raise PathSecurityError("Metadata value %r must be a string." % key)
    return result


# ---------------------------------------------------------------------------
# Input snapshots and private working area
# ---------------------------------------------------------------------------


def read_input_file(path):
    """Read an explicit user input, pinned against later path swaps.

    The file is opened before inspection and read through the resulting
    descriptor, so a symlink/rename race after validation cannot redirect
    the read.
    """
    fd = os.open(path, os.O_RDONLY)
    try:
        mode = os.fstat(fd).st_mode
        if stat.S_ISDIR(mode):
            raise IsADirectoryError("%s is a directory." % path)
        if not stat.S_ISREG(mode):
            raise PathSecurityError("%s is not a regular file." % path)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(fd)


def read_planned_file(path):
    """Read a file that is part of the plan: symlinks are refused."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise PathSecurityError(
                "Refusing to read symbolic link: %s" % path
            ) from error
        raise
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise PathSecurityError("%s is not a regular file." % path)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(fd)


def private_workdir():
    """Create a fresh 0700 directory that no one else can place links in."""
    return tempfile.mkdtemp(prefix="handwrite-work-")


def write_private(directory, name, data):
    path = os.path.join(directory, name)
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def planned_codepoints(characters_dir):
    """Return the decimal named character directories produced this run."""
    codepoints = []
    for name in os.listdir(characters_dir):
        if name and all("0" <= char <= "9" for char in name):
            codepoint = int(name)
            if is_codepoint(codepoint) and stat.S_ISDIR(
                os.lstat(os.path.join(characters_dir, name)).st_mode
            ):
                codepoints.append(codepoint)
    return sorted(set(codepoints))


# ---------------------------------------------------------------------------
# No-follow directory traversal and publication
# ---------------------------------------------------------------------------
#
# Tokens are either POSIX directory file descriptors (held open for the
# lifetime of the context) or plain directory paths on the Windows
# fallback. Every write goes through a token, never through a path that is
# re-resolved from scratch.


@contextlib.contextmanager
def root_directory(path):
    """Open an explicit user chosen root directory.

    The root itself may be a symlink (the user named it explicitly); every
    descendant must be real.
    """
    if _HAS_OPENAT:
        token = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield token
        finally:
            os.close(token)
    else:
        if not os.path.isdir(path):
            raise NotADirectoryError(path)
        yield os.path.abspath(path)


@contextlib.contextmanager
def child_directory(parent, name, create=False):
    """Enter ``name`` below a held directory token.

    Symbolic links and non-directories are refused. With ``create=True`` a
    missing directory is created; an existing real directory is reused.
    """
    if _HAS_OPENAT:
        try:
            token = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent,
            )
        except OSError as error:
            if error.errno == errno.ENOENT and create:
                os.mkdir(name, 0o755, dir_fd=parent)
                try:
                    token = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent,
                    )
                except OSError as reopen_error:
                    if reopen_error.errno in (
                        errno.ELOOP,
                        errno.EMLINK,
                        errno.ENOTDIR,
                    ):
                        raise PathSecurityError(
                            "Refusing to traverse symbolic link or non-directory: %s"
                            % name
                        ) from reopen_error
                    raise
            elif error.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
                raise PathSecurityError(
                    "Refusing to traverse symbolic link or non-directory: %s" % name
                ) from error
            else:
                raise
        try:
            yield token
        finally:
            os.close(token)
    else:
        path = os.path.join(parent, name)
        if os.path.lexists(path):
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                raise PathSecurityError("Refusing to traverse symbolic link: %s" % path)
            if not stat.S_ISDIR(mode):
                raise NotADirectoryError(path)
        elif create:
            os.mkdir(path)
        else:
            raise FileNotFoundError(path)
        yield path


def publish_bytes(parent, name, data):
    """Create/overwrite ``name`` below a held directory, never via a link."""
    if _HAS_OPENAT:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, 0o644, dir_fd=parent)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.EMLINK):
                raise PathSecurityError(
                    "Refusing to write through symbolic link: %s" % name
                ) from error
            raise
        try:
            os.write(fd, data if isinstance(data, bytes) else data.encode("utf-8"))
        finally:
            os.close(fd)
    else:
        path = os.path.join(parent, name)
        if os.path.lexists(path) and stat.S_ISLNK(os.lstat(path).st_mode):
            raise PathSecurityError(
                "Refusing to write through symbolic link: %s" % path
            )
        with open(path, "wb") as handle:
            handle.write(data)


def publish_file(source, parent, name):
    """Publish an existing regular file below a held directory."""
    with open(source, "rb") as handle:
        publish_bytes(parent, name, handle.read())


def verify_planned_file(root_dir, *parts):
    """Assert ``root_dir/parts`` is a regular non-symlink file inside root."""
    if not parts:
        raise PathSecurityError("Empty planned file path.")
    with contextlib.ExitStack() as stack:
        token = stack.enter_context(root_directory(root_dir))
        for component in parts[:-1]:
            token = stack.enter_context(child_directory(token, component))
        leaf = parts[-1]
        if _HAS_OPENAT:
            try:
                fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=token)
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.EMLINK):
                    raise PathSecurityError(
                        "Refusing to read symbolic link: %s"
                        % os.path.join(root_dir, *parts)
                    ) from error
                raise
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise PathSecurityError(
                        "Not a regular file: %s" % os.path.join(root_dir, *parts)
                    )
            finally:
                os.close(fd)
        else:
            path = os.path.join(root_dir, *parts)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise PathSecurityError("Unsafe planned file: %s" % path)

    root = os.path.realpath(root_dir)
    resolved = os.path.realpath(os.path.join(root_dir, *parts))
    if os.path.commonpath((root, resolved)) != root:
        raise PathSecurityError("Planned file escapes its directory: %s" % resolved)
    return os.path.join(root_dir, *parts)


def publish_characters(characters_dir, preserve_dir, codepoints, suffixes):
    """Safely mirror planned ``<cp>/<cp><suffix>`` derivatives to a keep dir."""
    with root_directory(preserve_dir) as root:
        for codepoint in codepoints:
            name = str(codepoint)
            source_dir = os.path.join(characters_dir, name)
            if not stat.S_ISDIR(os.lstat(source_dir).st_mode):
                continue
            with child_directory(root, name, create=True) as target_dir:
                for suffix in suffixes:
                    source = os.path.join(source_dir, name + suffix)
                    if os.path.isfile(source):
                        publish_file(source, target_dir, name + suffix)


# ---------------------------------------------------------------------------
# Font filename and safe font publication
# ---------------------------------------------------------------------------


def sanitize_font_filename(name):
    """Reduce a requested font name to a safe basename.

    Neutralises POSIX traversal (``../``, absolute paths) and Windows path
    forms (backslashes, drive letters such as ``C:`` and NTFS alternate
    data streams) regardless of the host operating system. Chinese and
    other Unicode names are preserved.
    """
    if not isinstance(name, str) or not name:
        raise PathSecurityError("Font filename is missing.")
    if "\x00" in name or any(ord(char) < 32 for char in name):
        raise PathSecurityError("Font filename contains control characters.")

    text = name.replace("\\", "/")
    # POSIX directory traversal and absolute paths -> keep basename only.
    text = text.rsplit("/", 1)[-1]
    # Windows drive prefixes (C:name) and alternate data streams (name:x).
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    # Windows strips trailing spaces/dots from file names.
    text = text.rstrip(" .")
    if not text or text in (".", "..") or set(text) == {"."}:
        raise PathSecurityError("Unsafe font filename: %r" % name)
    return text


def resolve_font_path(outdir, filename):
    """Plan the final TTF path, preserving the historical numbering quirk.

    ``MyFont.ttf`` colliding with an existing file becomes
    ``MyFont (1).ttf``; a third run becomes ``MyFont (1) (1).ttf`` because
    numbering restarts from the base name on every invocation.
    """
    root = os.path.realpath(outdir)
    base = sanitize_font_filename(filename)
    candidate = base if base.endswith(".ttf") else base + ".ttf"
    candidate = os.path.join(root, candidate)
    while os.path.exists(candidate):
        candidate = os.path.splitext(candidate)[0] + " (1).ttf"
    if os.path.commonpath((root, os.path.dirname(candidate))) != root:
        raise PathSecurityError("Font output escapes its directory.")
    return candidate


def stage_font_path(outdir):
    """Reserved private staging path for the TTF inside the output dir."""
    fd, path = tempfile.mkstemp(
        prefix=".handwrite-stage-", suffix=".ttf", dir=os.path.realpath(outdir)
    )
    os.close(fd)
    return path


def publish_font(staged_ttf, outdir, filename):
    """Move a staged TTF to its numbered name without following any link.

    ``os.replace`` replaces a symbolic link itself instead of writing
    through it, so pre-planted links cannot redirect the font.
    """
    target = resolve_font_path(outdir, filename)
    os.replace(staged_ttf, target)
    return target
