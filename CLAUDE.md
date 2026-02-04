# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Snort Rule Builder is a Tkinter-based GUI application for interactively creating Snort IDS/IPS rules. The application provides a form-based interface with real-time rule preview.

## Running the Application

```bash
python snort_rule_builder/snort_rule_builder.py
```

Requires Python 3 with Tkinter (included in standard Python installations).

## Architecture

Single-file application (`snort_rule_builder/snort_rule_builder.py`) with one main class:

- **SnortRuleBuilder**: Main application class containing all UI components and logic
  - `create_widgets()`: Builds the entire UI (header, options, content detection, flow control sections)
  - `generate_rule()`: Assembles Snort rule string from form fields; called automatically on any field change via `trace_add` callbacks
  - Rule format: `action protocol src_ip src_port direction dst_ip dst_port (options;)`

## Key Implementation Details

- All form fields use Tkinter `StringVar`/`BooleanVar` with automatic rule regeneration on change
- Content field accepts both hex (`|00 01 02|`) and string (`"text"`) formats
- Threshold option requires all four sub-fields (type, track, count, seconds) to be included in output
- Rules are saved in append mode to allow building rule files incrementally
