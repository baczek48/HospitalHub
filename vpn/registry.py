"""Registry of VPN providers.

Deliberately dumb: it holds providers and hands them back by id.  It does not
connect, does not fall back, does not decide anything.  Choosing *what to do*
with a provider stays with the caller, and today the caller is still the old
`vpn_connect` module — nothing here is wired into the running application.

The one thing it does actively is refuse a duplicate id: two providers
answering to the same name is the kind of mistake that shows up much later as
"why did it use the other client".
"""

from __future__ import annotations

from typing import Iterator

from .provider import VpnProvider

__all__ = ["VpnRegistry", "DuplicateProviderIdError", "UnknownProviderError",
           "default_registry"]


class DuplicateProviderIdError(ValueError):
    """Two providers claim the same id."""


class UnknownProviderError(KeyError):
    """A required provider is not registered."""


class VpnRegistry:
    def __init__(self, providers: list[VpnProvider] | None = None):
        self._providers: dict[str, VpnProvider] = {}
        for provider in providers or []:
            self.register(provider)

    # -- registration ------------------------------------------------------ #

    def register(self, provider: VpnProvider, replace: bool = False) -> VpnProvider:
        """Add a provider. Raises on a duplicate id unless `replace` is set."""
        provider_id = getattr(provider, "id", "")
        if not provider_id or not isinstance(provider_id, str):
            raise ValueError("provider musi mieć niepuste, tekstowe id")
        if not replace and provider_id in self._providers:
            existing = type(self._providers[provider_id]).__name__
            raise DuplicateProviderIdError(
                f"provider o id {provider_id!r} jest już zarejestrowany "
                f"({existing})")
        self._providers[provider_id] = provider
        return provider

    def unregister(self, provider_id: str) -> bool:
        return self._providers.pop(provider_id, None) is not None

    def clear(self) -> None:
        self._providers.clear()

    # -- lookup ------------------------------------------------------------ #

    def get(self, provider_id: str) -> VpnProvider | None:
        """Provider or None — the safe lookup."""
        return self._providers.get(provider_id)

    def require(self, provider_id: str) -> VpnProvider:
        """Provider or :class:`UnknownProviderError` — the strict lookup."""
        provider = self._providers.get(provider_id)
        if provider is None:
            known = ", ".join(sorted(self._providers)) or "brak"
            raise UnknownProviderError(
                f"nieznany provider {provider_id!r} (zarejestrowane: {known})")
        return provider

    def find_by_legacy_name(self, legacy_name: str) -> VpnProvider | None:
        """Find a provider by the string vaults store today (e.g. 'FortiClient')."""
        wanted = str(legacy_name).strip()
        for provider in self._providers.values():
            if getattr(provider, "legacy_name", "") == wanted:
                return provider
        return None

    def all(self) -> list[VpnProvider]:
        return [self._providers[key] for key in sorted(self._providers)]

    def ids(self) -> list[str]:
        return sorted(self._providers)

    # -- dunder ------------------------------------------------------------ #

    def __contains__(self, provider_id: object) -> bool:
        return provider_id in self._providers

    def __len__(self) -> int:
        return len(self._providers)

    def __iter__(self) -> Iterator[VpnProvider]:
        return iter(self.all())

    def __repr__(self) -> str:
        return f"<VpnRegistry {len(self)} providers: {', '.join(self.ids()) or '—'}>"


#: Process-wide registry.  Created empty here and filled exactly once, by
#: ``vpn/__init__.py`` (the package's single initialisation point), with
#: :data:`vpn.providers.BUILTIN_PROVIDERS`.  Nothing in the running
#: application reads it for connect/disconnect/status/launch.
default_registry = VpnRegistry()
