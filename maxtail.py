#!/usr/bin/env python3

"""
Write data to a file, ensuring the file doesn't exceed the specified maximum
size.
"""

import argparse
import logging
import numbers
import os
import re
import sys

logging.basicConfig(
        format="%(module)s:%(lineno)s: %(levelname)s: %(message)s",
        level=logging.INFO)
logger = logging.getLogger(__name__)

SIZE_DEFAULT_S = "10mb"
BUFSIZE_DEFAULT_S = "10mb"
THRESHOLD_DEFAULT_S = "4kb"
# Populated by __main__
SIZE_DEFAULT = None
BUFSIZE_DEFAULT = None
THRESHOLD_DEFAULT = None

def format_size(num, base=1024):
    "Format a size string (e.g. 12 MB)"
    suffixes = ("B", "KB", "MB", "GB", "TB", "EB")
    mag = 0
    curr = num
    while curr > base and mag+1 < len(suffixes):
        mag += 1
        curr /= base
    return "{} {}".format(curr, suffixes[mag])

def parse_size(size, base=1024, noraise=False):
    "Parse a size string (e.g. 12mb)"
    suffixes = {
        "": 0, "b": 0,
        "k": 1, "kb": 1,
        "m": 2, "mb": 2,
        "g": 3, "gb": 3,
        "t": 4, "tb": 4
    }
    # Remove spaces and commas, normalize case
    s = re.sub("[, ]", "", size).lower()
    # Parse number and suffix
    m = re.match(r"^([0-9.]+)([a-z]*)$", s)
    if m is None:
        if noraise:
            logger.warning("Failed to parse size {!r}".format(size))
            return
        else:
            raise ValueError("Failed to parse size {!r}".format(size))
    coeff = float(m.group(1))
    suffix = m.group(2)
    if "i" in suffix:
        # "ibibytes" aren't supported here
        logger.warning("Removing 'i' from suffix {!r}".format(suffix))
        suffix = suffix.replace("i", "")
    if suffix not in suffixes:
        if noraise:
            logger.warning("Invalid suffix {!r}".format(suffix))
            return
        else:
            raise ValueError("Invalid suffix {!r}".format(suffix))
    result = coeff * base ** suffixes[suffix]
    return round(result)

def unique_path(name, dirname=None, suffix=None):
    "Create a unique path"
    def format_path(d, n, i, s):
        "format (dir, name, index, suffix) as a file path"
        p = os.path.join(d, n) if d is not None else n
        # Always add index if suffix isn't given
        if i > 0 or s is None:
            p = "{}.{}".format(p, i)
        if s is not None and len(s) > 0:
            # Add a period (unless suffix has one) and then add suffix
            if not s.startswith("."):
                p += "."
            p += s
        logger.debug("({!r}/{!r}, {}, {!r}) -> {!r}".format(d, n, i, s, p))
        return p

    idx = 0
    p = format_path(dirname, name, idx, suffix)
    while os.path.exists(p):
        idx += 1
        p = format_path(dirname, name, idx, suffix)
    return p

def truncate_file(fpath, size,
        suffix=".temp",
        bufsize=BUFSIZE_DEFAULT,
        whole_lines=False,
        eol_str=os.linesep):
    fsize = os.stat(fpath).st_size
    if fsize < size:
        logger.warning("Not truncating {!r}, file size {} < max {}".format(
            fpath, fsize, size))
        return 0
    # Write last N bytes to a temp file
    nbytes = 0
    tmppath = unique_path(fpath, suffix=suffix)
    logger.debug("Truncating {!r} to {!r}".format(fpath, tmppath))
    with open(fpath, "rb") as ifobj:
        ifobj.seek(-size, os.SEEK_END)
        if whole_lines:
            # Discard text up until the next newline
            data = ifobj.peek()
            pos = data.find(bytes(eol_str, "ascii"))
            if pos > 0:
                logger.debug("Discarding {} bytes ({!r})".format(
                    pos, data[:pos]))
                ifobj.seek(pos+len(os.linesep), os.SEEK_CUR)
        with open(tmppath, "wb") as ofobj:
            buf = ifobj.read(bufsize)
            if len(buf) > 0:
                nbytes += ofobj.write(buf)
    borig = "{} bytes ({})".format(fsize, format_size(fsize))
    bfinal = "{} bytes ({})".format(nbytes, format_size(nbytes))
    logger.debug("Wrote last {} (of {} total) from {} to {}".format(
        bfinal, borig, fpath, tmppath))
    logger.debug("Renaming {} over {}".format(tmppath, fpath))
    # Move the temp file over the original
    os.rename(tmppath, fpath)
    return nbytes

def lines_from(fd=None, encoding=None):
    "Read lines from src"
    if fd is None:
        fd = sys.stdin.fileno()
    with open(fd, "rt", encoding=encoding) as fobj:
        yield from fobj

class WriteTruncate:
    """
    Write to a file, ensuring the file does not grow beyond a certain size.
    """
    def __init__(self, maxsize,
            fpath=None,
            append=False,
            encoding=None,
            threshold=None,
            whole_lines=False,
            eol_str=os.linesep):
        self._path = fpath
        self._append = append
        self._encoding = encoding
        self._whole_lines = whole_lines
        self._eol_str = eol_str

        if isinstance(maxsize, numbers.Number):
            self._max = maxsize
        else:
            self._max = parse_size(maxsize)
        if threshold is None:
            self._threshold = THRESHOLD_DEFAULT
        elif isinstance(threshold, numbers.Number):
            self._threshold = threshold
        else:
            self._threshold = parse_size(threshold)

        self._fobj = None
        self._first_open = True

    def _ensure_open(self):
        "Ensure self._fobj refers to an open file"
        if self._fobj is None or self._fobj.closed:
            mode = "at"
            if self._first_open and not self._append:
                mode = "wt"
            kws = {}
            if self._encoding is not None:
                kws["encoding"] = self._encoding
            self._fobj = open(self._path, mode, **kws)
            logger.debug("Opened {!r} mode {!r}".format(self._path, mode))
            self._first_open = False

    def _maybe_truncate(self, exact=False):
        "Ensure the file we're writing to isn't larger than the max size"
        self._fobj.flush()      # Ensure nothing is cached
        fsize = os.stat(self._path).st_size
        maxsize = self._max
        if not exact:
            maxsize += self._threshold
        if fsize > maxsize:
            # Time to truncate the file
            logger.debug("Closing {} for truncation".format(self._path))
            self._fobj.close()
            nb = truncate_file(self._path, self._max,
                    whole_lines=self._whole_lines,
                    eol_str=self._eol_str)
            logger.debug("Truncated {!r} to {} bytes ({})".format(
                self._path, nb, format_size(nb)))

    def set_encoding(self, e):
        self._encoding = e

    def set_append(self, value):
        self._append = value

    def write(self, line, eol=None, suppress=False):
        "Write a line to the file"
        self._ensure_open()
        b = self._fobj.write(line)
        if eol is not None:
            b += self._fobj.write(eol)
        if not suppress:
            self._fobj.flush()
            self._maybe_truncate()
        return b

    def close(self):
        self._ensure_open()
        self._maybe_truncate(exact=True)
        self._fobj.close()
        logger.debug("Closed {} for the last time".format(self._path))

def main():
    ap = argparse.ArgumentParser(epilog="""
SIZE refers to a number followed by a size designation: one of "b", "k", "kb",
"m", "mb", "g", "gb", "t", or "tb". No size designation implies "b". For
example, the values "2048", "2 048", "2K", "2kb", "2 K", and "2 KB" all mean
two kilobytes (unless --base10, in which case "two kilobytes" means 2000B).
Sizes are not case-sensitive.
""")
    ap.add_argument("-f", "--fd",
        help="read from file descriptor %(metavar)s instead of stdin")
    ap.add_argument("-o", "--output", required=True, metavar="PATH",
        help="write output to %(metavar)s")
    ap.add_argument("-a", "--append", action="store_true",
        help="append output to file instead of overwriting")
    ap.add_argument("-e", "--encoding", help="input/output encoding")
    ap.add_argument("-t", "--threshold", metavar="SIZE",
        default=THRESHOLD_DEFAULT_S,
        help="truncate once file exceeds the max size by this many bytes "
             "(default: %(default)s)")
    ap.add_argument("-w", "--wholelines", action="store_true",
        help="truncate the file on a line boundary")
    ap.add_argument("-S", "--sep", metavar="STR", default=os.linesep,
        help="use %(metavar)s as a \"line boundary\" (default: %(default)r)")

    ap.add_argument("-s", "--size", default=SIZE_DEFAULT_S,
        help="maximum output size (default: %(default)s)")
    ap.add_argument("--base10", action="store_true",
        help="use base-10 instead of base-2")

    ag = ap.add_argument_group("Logging")
    ag = ag.add_mutually_exclusive_group()
    ag.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    ag.add_argument("-q", "--quiet", action="store_true", help="be quiet")

    args = ap.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.ERROR)

    base = 1000 if args.base10 else 1024
    msize = parse_size(args.size, base=base)
    logger.info("Limiting output to {}".format(format_size(msize)))

    nbytes = 0      # bytes written
    wt = WriteTruncate(msize,
            fpath=args.output,
            append=args.append,
            encoding=args.encoding,
            threshold=args.threshold,
            whole_lines=args.wholelines,
            eol_str=args.sep)
    for line in lines_from(fd=args.fd, encoding=args.encoding):
        nbytes += wt.write(line)
    wt.close()

if __name__ == "__main__":
    SIZE_DEFAULT = parse_size(SIZE_DEFAULT_S)
    BUFSIZE_DEFAULT = parse_size(BUFSIZE_DEFAULT_S)
    THRESHOLD_DEFAULT = parse_size(THRESHOLD_DEFAULT_S)
    main()
