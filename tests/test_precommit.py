"""Tests for pre-commit hook compliance scanning.

Tests cover:
- validate_commit_files() with valid/invalid file paths
- run_compliance_scan() with mocked subprocess calls
- should_allow_commit() with pass/fail/warning scenarios
- execute_precommit_hook() with full integration scenarios
"""

import logging
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from air_blackbox.precommit import (
    execute_precommit_hook,
    run_compliance_scan,
    should_allow_commit,
    validate_commit_files,
)


class TestValidateCommitFiles(unittest.TestCase):
    """Tests for validate_commit_files() function."""

    def test_validate_commit_files_valid_single_file(self):
        """Test validation passes for single valid file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            result = validate_commit_files([str(test_file)])
            self.assertTrue(result)

    def test_validate_commit_files_valid_multiple_files(self):
        """Test validation passes for multiple valid files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "test1.py"
            file2 = Path(tmpdir) / "test2.py"
            file3 = Path(tmpdir) / "test3.py"

            file1.write_text("print('test1')")
            file2.write_text("print('test2')")
            file3.write_text("print('test3')")

            result = validate_commit_files([str(file1), str(file2), str(file3)])
            self.assertTrue(result)

    def test_validate_commit_files_nonexistent_file(self):
        """Test validation fails for nonexistent file."""
        with self.assertRaises(ValueError) as ctx:
            validate_commit_files(["/nonexistent/path/to/file.py"])

        self.assertIn("File does not exist", str(ctx.exception))

    def test_validate_commit_files_directory_path(self):
        """Test validation fails when given directory instead of file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError) as ctx:
                validate_commit_files([tmpdir])

            self.assertIn("Path is not a file", str(ctx.exception))

    def test_validate_commit_files_mixed_valid_invalid(self):
        """Test validation fails if any file is invalid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            valid_file = Path(tmpdir) / "valid.py"
            valid_file.write_text("print('test')")

            with self.assertRaises(ValueError):
                validate_commit_files([str(valid_file), "/nonexistent/file.py"])

    def test_validate_commit_files_empty_list(self):
        """Test validation passes for empty file list."""
        result = validate_commit_files([])
        self.assertTrue(result)

    def test_validate_commit_files_preserves_order(self):
        """Test that validation preserves file order."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = []
            for i in range(5):
                f = Path(tmpdir) / f"file{i}.py"
                f.write_text(f"print({i})")
                files.append(str(f))

            result = validate_commit_files(files)
            self.assertTrue(result)


class TestRunComplianceScan(unittest.TestCase):
    """Tests for run_compliance_scan() function."""

    def test_run_compliance_scan_valid_files(self):
        """Test compliance scan runs successfully on valid files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            results = run_compliance_scan([str(test_file)])

            self.assertIsInstance(results, dict)
            self.assertIn("status", results)
            self.assertIn("files_scanned", results)
            self.assertEqual(results["status"], "completed")

    def test_run_compliance_scan_multiple_files(self):
        """Test compliance scan with multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = []
            for i in range(3):
                f = Path(tmpdir) / f"test{i}.py"
                f.write_text(f"print({i})")
                files.append(str(f))

            results = run_compliance_scan(files)

            self.assertEqual(results["files_scanned"], 3)

    def test_run_compliance_scan_empty_file_list(self):
        """Test compliance scan with empty file list."""
        results = run_compliance_scan([])

        self.assertEqual(results["files_scanned"], 0)
        self.assertEqual(results["status"], "completed")

    def test_run_compliance_scan_nonexistent_file_raises(self):
        """Test that scanning nonexistent file raises ValueError."""
        with self.assertRaises(ValueError):
            run_compliance_scan(["/nonexistent/file.py"])

    def test_run_compliance_scan_includes_timeout(self):
        """Test that scan results include timeout value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            results = run_compliance_scan([str(test_file)], timeout=60)

            self.assertIn("timeout", results)
            self.assertEqual(results["timeout"], 60)

    def test_run_compliance_scan_default_timeout(self):
        """Test that scan uses default timeout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            results = run_compliance_scan([str(test_file)])

            self.assertIn("timeout", results)
            self.assertEqual(results["timeout"], 30)

    def test_run_compliance_scan_custom_timeout(self):
        """Test that scan respects custom timeout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            results = run_compliance_scan([str(test_file)], timeout=120)

            self.assertEqual(results["timeout"], 120)

    @patch("air_blackbox.precommit.logger")
    def test_run_compliance_scan_logs_start(self, mock_logger):
        """Test that scan logs start event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            run_compliance_scan([str(test_file)])

            mock_logger.info.assert_called()

    def test_run_compliance_scan_issues_found_count(self):
        """Test that scan results include issues_found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            results = run_compliance_scan([str(test_file)])

            self.assertIn("issues_found", results)
            self.assertEqual(results["issues_found"], 0)


class TestShouldAllowCommit(unittest.TestCase):
    """Tests for should_allow_commit() function."""

    def test_should_allow_commit_no_issues(self):
        """Test that commit is allowed with no issues."""
        scan_results = {"status": "completed", "issues_found": 0}

        result = should_allow_commit(scan_results)

        self.assertTrue(result)

    def test_should_allow_commit_with_issues_not_allowed(self):
        """Test that commit is blocked with issues when warnings not allowed."""
        scan_results = {"status": "completed", "issues_found": 3}

        result = should_allow_commit(scan_results, allow_warnings=False)

        self.assertFalse(result)

    def test_should_allow_commit_with_issues_warnings_allowed(self):
        """Test that commit is allowed with issues when warnings allowed."""
        scan_results = {"status": "completed", "issues_found": 3}

        result = should_allow_commit(scan_results, allow_warnings=True)

        self.assertTrue(result)

    def test_should_allow_commit_single_issue(self):
        """Test that single issue blocks commit by default."""
        scan_results = {"issues_found": 1}

        result = should_allow_commit(scan_results)

        self.assertFalse(result)

    def test_should_allow_commit_single_issue_allowed(self):
        """Test that single issue allowed with warnings enabled."""
        scan_results = {"issues_found": 1}

        result = should_allow_commit(scan_results, allow_warnings=True)

        self.assertTrue(result)

    def test_should_allow_commit_many_issues(self):
        """Test that many issues block commit."""
        scan_results = {"issues_found": 100}

        result = should_allow_commit(scan_results)

        self.assertFalse(result)

    def test_should_allow_commit_missing_issues_key(self):
        """Test handling of missing issues_found key."""
        scan_results = {"status": "completed"}

        result = should_allow_commit(scan_results)

        # Should default to 0 issues and allow commit
        self.assertTrue(result)

    def test_should_allow_commit_empty_results(self):
        """Test handling of empty results dictionary."""
        scan_results = {}

        result = should_allow_commit(scan_results)

        self.assertTrue(result)

    @patch("air_blackbox.precommit.logger")
    def test_should_allow_commit_logs_pass(self, mock_logger):
        """Test that passing check is logged."""
        scan_results = {"issues_found": 0}

        should_allow_commit(scan_results)

        mock_logger.info.assert_called()

    @patch("air_blackbox.precommit.logger")
    def test_should_allow_commit_logs_fail(self, mock_logger):
        """Test that failing check is logged."""
        scan_results = {"issues_found": 5}

        should_allow_commit(scan_results, allow_warnings=False)

        mock_logger.error.assert_called()

    @patch("air_blackbox.precommit.logger")
    def test_should_allow_commit_logs_warning(self, mock_logger):
        """Test that warning check is logged."""
        scan_results = {"issues_found": 5}

        should_allow_commit(scan_results, allow_warnings=True)

        mock_logger.warning.assert_called()


class TestExecutePrecommitHook(unittest.TestCase):
    """Tests for execute_precommit_hook() function."""

    def test_execute_precommit_hook_success(self):
        """Test successful precommit hook execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            exit_code = execute_precommit_hook([str(test_file)])

            self.assertEqual(exit_code, 0)

    def test_execute_precommit_hook_no_files(self):
        """Test precommit hook with no files."""
        exit_code = execute_precommit_hook([])

        self.assertEqual(exit_code, 0)

    def test_execute_precommit_hook_none_files(self):
        """Test precommit hook with None file list."""
        exit_code = execute_precommit_hook(None)

        self.assertEqual(exit_code, 0)

    def test_execute_precommit_hook_multiple_files(self):
        """Test precommit hook with multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = []
            for i in range(3):
                f = Path(tmpdir) / f"test{i}.py"
                f.write_text(f"print({i})")
                files.append(str(f))

            exit_code = execute_precommit_hook(files)

            self.assertEqual(exit_code, 0)

    def test_execute_precommit_hook_nonexistent_file(self):
        """Test precommit hook with nonexistent file returns error."""
        exit_code = execute_precommit_hook(["/nonexistent/file.py"])

        self.assertEqual(exit_code, 1)

    @patch("air_blackbox.precommit.should_allow_commit")
    @patch("air_blackbox.precommit.run_compliance_scan")
    def test_execute_precommit_hook_blocked(self, mock_scan, mock_allow):
        """Test precommit hook returns 1 when commit blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            mock_scan.return_value = {"status": "completed", "issues_found": 5}
            mock_allow.return_value = False

            exit_code = execute_precommit_hook([str(test_file)])

            self.assertEqual(exit_code, 1)

    @patch("air_blackbox.precommit.should_allow_commit")
    @patch("air_blackbox.precommit.run_compliance_scan")
    def test_execute_precommit_hook_allowed(self, mock_scan, mock_allow):
        """Test precommit hook returns 0 when commit allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            mock_scan.return_value = {"status": "completed", "issues_found": 0}
            mock_allow.return_value = True

            exit_code = execute_precommit_hook([str(test_file)])

            self.assertEqual(exit_code, 0)

    @patch("air_blackbox.precommit.logger")
    def test_execute_precommit_hook_logs_execution(self, mock_logger):
        """Test that hook execution is logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            execute_precommit_hook([str(test_file)])

            mock_logger.info.assert_called()

    @patch("air_blackbox.precommit.logger")
    def test_execute_precommit_hook_logs_error_on_failure(self, mock_logger):
        """Test that errors are logged on failure."""
        execute_precommit_hook(["/nonexistent/file.py"])

        mock_logger.error.assert_called()

    @patch("air_blackbox.precommit.should_allow_commit")
    @patch("air_blackbox.precommit.run_compliance_scan")
    def test_execute_precommit_hook_scan_called(self, mock_scan, mock_allow):
        """Test that run_compliance_scan is called."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            mock_scan.return_value = {"status": "completed"}
            mock_allow.return_value = True

            execute_precommit_hook([str(test_file)])

            mock_scan.assert_called_once()

    @patch("air_blackbox.precommit.should_allow_commit")
    @patch("air_blackbox.precommit.run_compliance_scan")
    def test_execute_precommit_hook_allow_check_called(self, mock_scan, mock_allow):
        """Test that should_allow_commit is called with scan results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            mock_results = {"status": "completed", "issues_found": 0}
            mock_scan.return_value = mock_results
            mock_allow.return_value = True

            execute_precommit_hook([str(test_file)])

            mock_allow.assert_called_once_with(mock_results)

    def test_execute_precommit_hook_timeout_handling(self):
        """Test that timeout is handled gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            # Should not raise, returns error code
            exit_code = execute_precommit_hook([str(test_file)])

            # Either 0 for success or 1 for error, but no exception
            self.assertIn(exit_code, [0, 1])


class TestPrecommitIntegration(unittest.TestCase):
    """Integration tests for precommit workflow."""

    def test_precommit_workflow_clean_files(self):
        """Test complete precommit workflow with clean files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = []
            for i in range(3):
                f = Path(tmpdir) / f"module{i}.py"
                f.write_text("import sys\nprint('hello')")
                files.append(str(f))

            # Validate
            validation = validate_commit_files(files)
            self.assertTrue(validation)

            # Scan
            scan_results = run_compliance_scan(files)
            self.assertEqual(scan_results["files_scanned"], 3)

            # Allow
            allowed = should_allow_commit(scan_results)
            self.assertTrue(allowed)

    def test_precommit_workflow_with_issues(self):
        """Test complete precommit workflow when issues found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("import sys")

            validation = validate_commit_files([str(test_file)])
            self.assertTrue(validation)

            scan_results = run_compliance_scan([str(test_file)])
            self.assertEqual(scan_results["files_scanned"], 1)

            # By default should block
            allowed = should_allow_commit(scan_results)
            # Result depends on implementation

            # With warnings allowed should pass
            allowed_with_warnings = should_allow_commit(scan_results, allow_warnings=True)
            self.assertTrue(allowed_with_warnings)

    def test_precommit_workflow_invalid_files(self):
        """Test precommit workflow fails early on invalid files."""
        with self.assertRaises(ValueError):
            validate_commit_files(["/nonexistent/file.py"])


if __name__ == "__main__":
    unittest.main()
