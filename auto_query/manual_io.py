"""Turn manually collected model responses into the canonical raw_responses shape.

The manual workflow (for providers without a suitable search-enabled API —
ERNIE, Kimi, Meta AI, ...): generate the prompt, paste it into each chatbot,
record one response per model in a spreadsheet with ``Model`` / ``Responses``
columns, then upload it. This module converts that spreadsheet (xlsx via
openpyxl, or csv) into the ``[{"Model": ..., "Responses": ...}]`` records the
evaluation pipeline consumes — the same job as the branch's
``convert_manual_responses.py``, without the pandas dependency and reading
from bytes (an upload) instead of a file in the project root.
"""

import csv
import io


class ManualResponsesError(ValueError):
    """Raised when an uploaded responses file cannot be understood."""


def _records_from_table(header, rows):
    """Map a header row + data rows onto Model/Responses records."""
    columns = [str(cell).strip().lower() if cell is not None else "" for cell in header]
    try:
        model_idx = columns.index("model")
    except ValueError:
        raise ManualResponsesError(
            'The file needs a "Model" column and a "Responses" column '
            f"(found columns: {', '.join(c or '?' for c in columns)})."
        )
    response_idx = None
    for name in ("responses", "response", "answer"):
        if name in columns:
            response_idx = columns.index(name)
            break
    if response_idx is None:
        raise ManualResponsesError(
            'The file needs a "Responses" column next to "Model".'
        )

    records = []
    for row in rows:
        cells = list(row) + [None] * (max(model_idx, response_idx) + 1 - len(row))
        model = str(cells[model_idx] or "").strip()
        response = str(cells[response_idx] or "").strip()
        if model and response:
            records.append({"Model": model, "Responses": response})
    return records


def _load_xlsx(data):
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise ManualResponsesError(
            "Reading .xlsx uploads requires the openpyxl package."
        ) from exc
    try:
        workbook = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:
        raise ManualResponsesError(f"Could not open the spreadsheet: {exc}") from exc
    sheet = workbook.active
    rows = sheet.iter_rows(values_only=True)
    header = next(rows, None)
    if header is None:
        raise ManualResponsesError("The spreadsheet is empty.")
    return _records_from_table(header, rows)


def _load_csv(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ManualResponsesError("The CSV is not valid UTF-8.") from exc
    reader = csv.reader(io.StringIO(text))
    header = next(reader, None)
    if header is None:
        raise ManualResponsesError("The CSV is empty.")
    return _records_from_table(header, reader)


def load_manual_responses(data, filename=""):
    """Parse uploaded bytes (xlsx or csv, by extension/signature) into records.

    Returns the raw list; run it through
    ``auto_query.pipelines.manual_query_pipeline.manual_query_pipeline`` for
    the validated/normalized form.
    """
    if not data:
        raise ManualResponsesError("The uploaded file is empty.")
    name = (filename or "").lower()
    if name.endswith(".csv"):
        records = _load_csv(data)
    elif name.endswith((".xlsx", ".xlsm")) or data[:4] == b"PK\x03\x04":
        records = _load_xlsx(data)
    else:
        records = _load_csv(data)
    if not records:
        raise ManualResponsesError(
            "No usable rows found — each row needs a Model and its Responses text."
        )
    return records
