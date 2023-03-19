from pathlib import Path
from typing import Any, Dict, Tuple, Type, TypeVar

from knot_resolver_manager.utils.modeling.base_value_type import BaseValueType


class UncheckedPath(BaseValueType):
    """
    Wrapper around pathlib.Path object. Can represent pretty much any Path. No checks are
    performed on the value. The value is taken as is.
    """

    _value: Path

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:

        super().__init__(source_value, object_path=object_path)
        self._object_path: str = object_path
        self._parents: Tuple[UncheckedPath, ...] = parents
        if isinstance(source_value, str):
            self._raw_value: str = source_value
            if self._parents:
                pp = map(lambda p: p.to_path(), self._parents)
                self._value: Path = Path(*pp, source_value)
            else:
                self._value: Path = Path(source_value)
        else:
            raise ValueError(f"expected file path in a string, got '{source_value}' with type '{type(source_value)}'.")

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, UncheckedPath):
            return False

        return o._value == self._value

    def __int__(self) -> int:
        raise RuntimeError("Path cannot be converted to type <int>")

    def to_path(self) -> Path:
        return self._value

    def serialize(self) -> Any:
        return self._raw_value

    def relative_to(self, parent: "UncheckedPath") -> "UncheckedPath":
        """return a path with an added parent part"""
        return UncheckedPath(self._raw_value, parents=(parent, *self._parents), object_path=self._object_path)

    UPT = TypeVar("UPT", bound="UncheckedPath")

    def reconstruct(self, cls: Type[UPT]) -> UPT:
        """
        Rebuild this object as an instance of its subclass. Practically, allows for conversions from
        """
        return cls(self._raw_value, parents=self._parents, object_path=self._object_path)

    @classmethod
    def json_schema(cls: Type["UncheckedPath"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class Dir(UncheckedPath):
    """
    Path, that is enforced to be:
    - an existing directory
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)
        if not self._value.is_dir():
            raise ValueError(f"path '{self._value}' does not point to an existing directory")


class AbsoluteDir(Dir):
    """
    Path, that is enforced to be:
    - absolute
    - an existing directory
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)
        if not self._value.is_absolute():
            raise ValueError("path not absolute")


class File(UncheckedPath):
    """
    Path, that is enforced to be:
    - an existing file
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)
        if not self._value.exists():
            raise ValueError("file does not exist")
        if not self._value.is_file():
            raise ValueError("path is not a file")


class FilePath(UncheckedPath):
    """
    Path, that is enforced to be:
    - parent of the last path segment is an existing directory
    - it does not point to a dir
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)
        p = self._value.parent
        if not p.exists() or not p.is_dir():
            raise ValueError(f"path '{self._value}' does not point inside an existing directory")
        if self._value.is_dir():
            raise ValueError("path points to a directory when we expected a file")


class CheckedPath(UncheckedPath):
    """
    Like UncheckedPath, but the file path is checked for being valid. So no non-existent directories in the middle,
    no symlink loops. This however means, that resolving of relative path happens while validating.
    """

    def __init__(
        self, source_value: Any, parents: Tuple["UncheckedPath", ...] = tuple(), object_path: str = "/"
    ) -> None:
        super().__init__(source_value, parents=parents, object_path=object_path)
        try:
            self._value = self._value.resolve(strict=False)
        except RuntimeError as e:
            raise ValueError("Failed to resolve given file path. Is there a symlink loop?") from e
