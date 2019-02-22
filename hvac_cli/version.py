import pbr.version

__all__ = ['__version__']

version_info = pbr.version.VersionInfo('hvac-cli')
try:
    __version__ = version_info.version_string()
except AttributeError:
    __version__ = None
