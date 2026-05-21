import pytest
from botocore.exceptions import ClientError

from scope.core.parallel import map_bounded


def test_map_bounded_preserves_order():
    results = map_bounded([3, 1, 2], lambda item: item * 2, max_workers=2)

    assert [result.index for result in results] == [0, 1, 2]
    assert [result.value for result in results] == [6, 2, 4]
    assert [result.ok for result in results] == [True, True, True]


def test_map_bounded_captures_errors():
    error = RuntimeError("bad item")

    def worker(item: int) -> int:
        if item == 2:
            raise error
        return item

    results = map_bounded([1, 2, 3], worker, max_workers=2)

    assert results[0].ok is True
    assert results[1].ok is False
    assert results[1].error is not None
    assert results[1].error.code == "RuntimeError"
    assert results[1].error.message == "bad item"
    assert results[1].exception is error
    assert results[2].ok is True


def test_map_bounded_preserves_client_error_code_and_message():
    error = ClientError(
        {
            "Error": {"Code": "AccessDeniedException", "Message": "denied"},
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        "GetBucketPolicy",
    )

    def worker(_item: int) -> int:
        raise error

    results = map_bounded([1], worker, max_workers=1)

    assert results[0].ok is False
    assert results[0].error is not None
    assert results[0].error.code == "AccessDeniedException"
    assert results[0].error.message == "denied"
    assert results[0].exception is error


def test_map_bounded_uses_class_name_for_callable_objects_without_name():
    class Worker:
        def __call__(self, item: int) -> int:
            raise RuntimeError(f"bad {item}")

    results = map_bounded([1], Worker(), max_workers=1)

    assert results[0].ok is False
    assert results[0].error is not None
    assert results[0].error.operation == "Worker"


def test_map_bounded_raise_on_error_reraises_original_error():
    error = RuntimeError("bad item")

    def worker(_item: int) -> int:
        raise error

    with pytest.raises(RuntimeError) as exc_info:
        map_bounded([1], worker, max_workers=1, raise_on_error=True)

    assert exc_info.value is error
