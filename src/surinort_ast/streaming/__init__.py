"""
Streaming API for memory-efficient processing of large IDS rule files.

This module provides generator-based APIs for processing rulesets that are too
large to fit comfortably in memory. Key features:

- Line-by-line parsing with constant memory usage
- Generator-based API for on-demand processing
- Batch streaming with configurable batch sizes
- Stream processors for filtering, transforming, and validation
- Parallel streaming with multiprocessing support
- Progress tracking and error recovery
- Checkpoint/resume capabilities

Performance characteristics:
- Constant memory usage regardless of file size
- 10k+ rules/second throughput on modern hardware
- <100MB memory for 100k+ rule files

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from .parser import (
    StreamBatch,
    StreamParser,
    stream_parse_file,
    stream_parse_file_parallel,
)
from .processor import (
    AggregateProcessor,
    FilterProcessor,
    StreamProcessor,
    TransformProcessor,
    ValidateProcessor,
)
from .writers import StreamWriter, StreamWriterJSON, StreamWriterText

__all__ = [
    "AggregateProcessor",
    "FilterProcessor",
    "StreamBatch",
    # Parser
    "StreamParser",
    # Processors
    "StreamProcessor",
    # Writers
    "StreamWriter",
    "StreamWriterJSON",
    "StreamWriterText",
    "TransformProcessor",
    "ValidateProcessor",
    "stream_parse_file",
    "stream_parse_file_parallel",
]
