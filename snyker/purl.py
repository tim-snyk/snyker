"""PURL model and helpers."""

from __future__ import annotations

from typing import Dict, Optional
from urllib.parse import quote

from pydantic import BaseModel


class PackageURL(BaseModel):
    """Represents a Package URL (purl).

    A purl is a URI that represents a software package in a mostly
    unambiguous way.
    See: https://github.com/package-url/purl-spec

    Attributes:
        type: The package "type" or package management system.
        namespace: Some name prefix such as a Maven groupid, a Docker image owner, etc.
        name: The name of the package.
        version: The version of the package.
        qualifiers: Extra qualifying data for a package such as an OS, architecture, etc.
        subpath: Extra subpath within a package, relative to the package root.
    """

    type: str
    namespace: Optional[str] = None
    name: str
    version: str
    qualifiers: Optional[Dict[str, str]] = None
    subpath: Optional[str] = None

    def to_string(self) -> str:
        """Encodes the PackageURL into a string for use in the Snyk API.

        Returns:
            A URI-encoded string representation of the PackageURL.
        """
        path = f"{self.type}/{self.name}@{self.version}"
        if self.namespace:
            path = f"{self.type}/{self.namespace}/{self.name}@{self.version}"

        purl = f"pkg:{path}"

        if self.qualifiers:
            qualifiers_str = "&".join([f"{k}={v}" for k, v in self.qualifiers.items()])
            purl = f"{purl}?{qualifiers_str}"

        if self.subpath:
            purl = f"{purl}#{self.subpath}"

        return quote(purl, safe="")
