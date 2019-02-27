import pbr.version

__all__ = ['__version__']

version_info = pbr.version.VersionInfo('hvac-cli')
__version__ = version_info.version_string()
