"""Audit engine for orchestrating security control execution."""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from auditor.core.control import Control
from auditor.core.finding import Status

logger = logging.getLogger(__name__)


class AuditEngine:
    """Orchestrates the execution of security controls."""

    def __init__(
        self,
        cloud_client,
        controls: List[Control],
        parallel: bool = True,
        max_workers: int = 10,
        frameworks: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ):
        """
        Initialize audit engine.

        Args:
            cloud_client: Azure or AWS client wrapper
            controls: List of controls to execute
            parallel: Whether to run controls in parallel
            max_workers: Maximum number of parallel workers
            frameworks: Optional list of frameworks to filter by
            services: Optional list of services to filter by
        """
        self.cloud_client = cloud_client
        self.controls = controls
        self.parallel = parallel
        self.max_workers = max_workers

        # Apply filters
        if frameworks:
            self.controls = [
                c for c in self.controls
                if c.framework in frameworks
            ]

        if services:
            self.controls = [
                c for c in self.controls
                if c.service in services
            ]

        logger.info(f"Initialized engine with {len(self.controls)} controls")

    async def run_audit(self) -> Dict[str, Any]:
        """
        Run all controls and generate results.

        Returns:
            Dictionary containing audit results and summary
        """
        start_time = datetime.utcnow()
        logger.info("Starting audit execution")

        all_findings = []

        if self.parallel:
            # Run controls in parallel
            logger.info(f"Running {len(self.controls)} controls in parallel")
            all_findings = await self._run_parallel()
        else:
            # Run controls sequentially
            logger.info(f"Running {len(self.controls)} controls sequentially")
            all_findings = await self._run_sequential()

        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Generate summary
        summary = self._generate_summary(all_findings)
        summary['duration_seconds'] = duration
        summary['start_time'] = start_time.isoformat()
        summary['end_time'] = end_time.isoformat()

        logger.info(f"Audit completed in {duration:.2f} seconds")
        logger.info(f"Total findings: {summary['total_findings']}")
        logger.info(f"Passed: {summary['passed']}, Failed: {summary['failed']}")

        return {
            'summary': summary,
            'findings': [f.to_dict() for f in all_findings],
            'controls_executed': len(self.controls)
        }

    async def _run_parallel(self) -> List:
        """Run controls in parallel with semaphore limiting."""
        semaphore = asyncio.Semaphore(self.max_workers)

        async def run_with_semaphore(control):
            async with semaphore:
                return await self._execute_control(control)

        tasks = [run_with_semaphore(control) for control in self.controls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten results
        all_findings = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Control execution failed: {result}")
            elif isinstance(result, list):
                all_findings.extend(result)

        return all_findings

    async def _run_sequential(self) -> List:
        """Run controls sequentially."""
        all_findings = []

        for control in self.controls:
            findings = await self._execute_control(control)
            all_findings.extend(findings)

        return all_findings

    async def _execute_control(self, control: Control) -> List:
        """
        Execute a single control.

        Args:
            control: Control to execute

        Returns:
            List of findings
        """
        try:
            logger.info(f"Executing control: {control.control_id}")
            findings = await control.audit(self.cloud_client)
            logger.info(f"Control {control.control_id} completed with {len(findings)} findings")
            return findings

        except Exception as e:
            logger.error(f"Error executing control {control.control_id}: {e}", exc_info=True)
            # Return error finding
            return [control._create_finding(
                status=Status.ERROR,
                resource_type="Control Execution",
                details={'error': str(e)}
            )]

    def _generate_summary(self, findings: List) -> Dict[str, Any]:
        """
        Generate summary statistics from findings.

        Args:
            findings: List of Finding objects

        Returns:
            Summary dictionary
        """
        total = len(findings)
        passed = sum(1 for f in findings if f.status == Status.PASS)
        failed = sum(1 for f in findings if f.status == Status.FAIL)
        warnings = sum(1 for f in findings if f.status == Status.WARNING)
        errors = sum(1 for f in findings if f.status == Status.ERROR)

        compliance_rate = (passed / total * 100) if total > 0 else 0

        # Framework breakdown
        frameworks = {}
        for finding in findings:
            fw = finding.framework
            if fw not in frameworks:
                frameworks[fw] = {'total': 0, 'passed': 0, 'failed': 0}

            frameworks[fw]['total'] += 1
            if finding.status == Status.PASS:
                frameworks[fw]['passed'] += 1
            elif finding.status == Status.FAIL:
                frameworks[fw]['failed'] += 1

        return {
            'total_findings': total,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'errors': errors,
            'compliance_rate': round(compliance_rate, 2),
            'frameworks': frameworks
        }
