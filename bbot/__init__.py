# version is dynamically set by hatch-vcs from git tags
try:
    from bbot._version import __version__
except ImportError:
    __version__ = "0.0.0"
