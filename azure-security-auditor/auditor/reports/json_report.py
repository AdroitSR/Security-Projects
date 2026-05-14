"""JSON report generator."""
import json
from pathlib import Path
from typing import Dict, Any


class JSONReport:
    """Generate JSON audit reports."""

    def __init__(self, results: Dict[str, Any]):
        """
        Initialize JSON report generator.

        Args:
            results: Audit results dictionary
        """
        self.results = results

    def generate(self, output_path: str):
        """
        Generate JSON report file.

        Args:
            output_path: Path to save JSON file
        """
        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        # Write JSON file
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
