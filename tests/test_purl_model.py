"""Tests for the PURL model."""
from snyker.purl import PackageURL


def test_purl_to_string_simple() -> None:
    """Test that a simple PURL is encoded correctly."""
    purl = PackageURL(
        type="npm",
        name="base64url",
        version="3.0.0",
    )
    assert purl.to_string() == "pkg%3Anpm%2Fbase64url%403.0.0"


def test_purl_to_string_with_namespace() -> None:
    """Test that a PURL with a namespace is encoded correctly."""
    purl = PackageURL(
        type="maven",
        namespace="org.apache.logging.log4j",
        name="log4j-core",
        version="2.17.1",
    )
    assert (
        purl.to_string()
        == "pkg%3Amaven%2Forg.apache.logging.log4j%2Flog4j-core%402.17.1"
    )


def test_purl_to_string_with_qualifiers() -> None:
    """Test that a PURL with qualifiers is encoded correctly."""
    purl = PackageURL(
        type="docker",
        name="snyk/snyk",
        version="latest",
        qualifiers={"os": "linux", "arch": "amd64"},
    )
    assert (
        purl.to_string()
        == "pkg%3Adocker%2Fsnyk%2Fsnyk%40latest%3Fos%3Dlinux%26arch%3Damd64"
    )


def test_purl_to_string_with_subpath() -> None:
    """Test that a PURL with a subpath is encoded correctly."""
    purl = PackageURL(
        type="github",
        namespace="package-url",
        name="purl-spec",
        version="a1b2c3d",
        subpath="README.md",
    )
    assert (
        purl.to_string()
        == "pkg%3Agithub%2Fpackage-url%2Fpurl-spec%40a1b2c3d%23README.md"
    )
