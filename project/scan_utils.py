import os
import tempfile

UUIDS_DIR = os.path.join(tempfile.gettempdir(), 'shepherd_scans')


def write_uuids_file(uuids):
    """Write UUIDs to a unique temp file and return its path."""
    os.makedirs(UUIDS_DIR, exist_ok=True)
    fd, path = tempfile.mkstemp(suffix='.txt', prefix='uuids_', dir=UUIDS_DIR)
    with os.fdopen(fd, 'w') as f:
        f.write('\n'.join(str(u) for u in uuids))
    return path


def read_uuids_file(path):
    """Read UUIDs from a temp file and delete it afterwards."""
    with open(path, 'r') as f:
        uuids = [line.strip() for line in f if line.strip()]
    os.remove(path)
    return uuids


def resolve_uuids(options):
    """Resolve UUIDs from --uuids or --uuids-file command options.

    Returns a list of UUID strings, or None if neither option was provided.
    """
    uuids_file = options.get('uuids_file')
    if uuids_file:
        return read_uuids_file(uuids_file)

    uuids_arg = options.get('uuids')
    if uuids_arg:
        return [u.strip() for u in uuids_arg.split(',') if u.strip()]

    return None


def add_common_scan_arguments(parser):
    """Add --uuids and --uuids-file arguments to a management command parser."""
    parser.add_argument(
        '--uuids',
        type=str,
        help='Comma-separated list of Asset UUIDs to process',
        required=False,
    )
    parser.add_argument(
        '--uuids-file',
        type=str,
        help='Path to a file containing Asset UUIDs (one per line)',
        required=False,
    )
