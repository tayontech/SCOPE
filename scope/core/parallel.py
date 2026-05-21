from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

from .models import ErrorRecord, TaskResult


T = TypeVar("T")
R = TypeVar("R")


def _operation_name(fn: Callable[[T], R]) -> str:
    return getattr(fn, "__name__", fn.__class__.__name__)


def _error_code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    return err.__class__.__name__


def _error_message(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Message"):
            return str(error["Message"])
    return str(err)


def map_bounded(
    items: Iterable[T],
    fn: Callable[[T], R],
    *,
    max_workers: int,
    raise_on_error: bool = False,
) -> list[TaskResult]:
    indexed_items = list(enumerate(items))
    results: list[TaskResult | None] = [None] * len(indexed_items)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fn, item): (index, item) for index, item in indexed_items}
        for future in as_completed(futures):
            index, item = futures[future]
            try:
                value = future.result()
                results[index] = TaskResult(index=index, item=item, ok=True, value=value)
            except Exception as err:
                error = ErrorRecord(
                    operation=_operation_name(fn),
                    resource=None,
                    code=_error_code(err),
                    message=_error_message(err),
                )
                results[index] = TaskResult(index=index, item=item, ok=False, error=error, exception=err)
                if raise_on_error:
                    raise

    return [result for result in results if result is not None]
