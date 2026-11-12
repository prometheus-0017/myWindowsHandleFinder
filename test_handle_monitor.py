"""
文件句柄监控工具测试用例
测试 HandleScanner 的核心业务逻辑，覆盖常见操作路径。
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import ctypes.wintypes

from handle_monitor import HandleEntry, HandleScanner


# ---------------------------------------------------------------------------
# 测试数据构造
# ---------------------------------------------------------------------------
def make_entry(
    process_name="test.exe",
    pid=1234,
    handle_type="File",
    handle_value="ABC",
    path=r"C:\Test\file.txt",
) -> HandleEntry:
    return HandleEntry(process_name, pid, handle_type, handle_value, path)


# ---------------------------------------------------------------------------
# 过滤功能测试
# ---------------------------------------------------------------------------
class TestFilterEntries:
    """测试 filter_entries 方法"""

    def test_empty_keyword_returns_all(self):
        entries = [make_entry(), make_entry(pid=5678)]
        result = HandleScanner.filter_entries(entries, "")
        assert result == entries
        assert len(result) == 2

    def test_filter_by_process_name(self):
        entries = [
            make_entry(process_name="notepad.exe"),
            make_entry(process_name="explorer.exe"),
            make_entry(process_name="notepad++.exe"),
        ]
        result = HandleScanner.filter_entries(entries, "notepad")
        assert len(result) == 2
        assert all(e.process_name.startswith("notepad") for e in result)

    def test_filter_by_pid(self):
        entries = [
            make_entry(pid=1234),
            make_entry(pid=5678),
            make_entry(pid=12345),
        ]
        result = HandleScanner.filter_entries(entries, "1234")
        assert len(result) == 2
        assert all(str(e.pid).startswith("1234") for e in result)

    def test_filter_by_path(self):
        entries = [
            make_entry(process_name="app1.exe", path=r"C:\Users\test\file.txt"),
            make_entry(process_name="app2.exe", path=r"C:\Program Files\app.exe"),
            make_entry(process_name="app3.exe", path=r"D:\Data\test.doc"),
        ]
        result = HandleScanner.filter_entries(entries, "test")
        assert len(result) == 2
        assert any("Users\\test" in e.path for e in result)
        assert any("test.doc" in e.path for e in result)

    def test_filter_case_insensitive(self):
        entries = [
            make_entry(process_name="Notepad.EXE"),
            make_entry(process_name="EXPLORER.exe"),
        ]
        result = HandleScanner.filter_entries(entries, "notepad")
        assert len(result) == 1
        assert result[0].process_name == "Notepad.EXE"

    def test_filter_no_match(self):
        entries = [make_entry(), make_entry()]
        result = HandleScanner.filter_entries(entries, "nonexistent")
        assert len(result) == 0

    def test_filter_empty_list(self):
        result = HandleScanner.filter_entries([], "test")
        assert result == []


# ---------------------------------------------------------------------------
# 排序功能测试
# ---------------------------------------------------------------------------
class TestSortEntries:
    """测试 sort_entries 方法"""

    def test_sort_by_process_name(self):
        entries = [
            make_entry(process_name="zebra.exe"),
            make_entry(process_name="alpha.exe"),
            make_entry(process_name="beta.exe"),
        ]
        result = HandleScanner.sort_entries(entries, "process")
        assert [e.process_name for e in result] == ["alpha.exe", "beta.exe", "zebra.exe"]

    def test_sort_by_pid_ascending(self):
        entries = [
            make_entry(pid=3000),
            make_entry(pid=1000),
            make_entry(pid=2000),
        ]
        result = HandleScanner.sort_entries(entries, "pid", reverse=False)
        assert [e.pid for e in result] == [1000, 2000, 3000]

    def test_sort_by_pid_descending(self):
        entries = [
            make_entry(pid=1000),
            make_entry(pid=3000),
            make_entry(pid=2000),
        ]
        result = HandleScanner.sort_entries(entries, "pid", reverse=True)
        assert [e.pid for e in result] == [3000, 2000, 1000]

    def test_sort_by_path(self):
        entries = [
            make_entry(path=r"C:\Zebra\file.txt"),
            make_entry(path=r"A:\Alpha\file.txt"),
            make_entry(path=r"B:\Beta\file.txt"),
        ]
        result = HandleScanner.sort_entries(entries, "path")
        assert result[0].path.startswith("A:")
        assert result[1].path.startswith("B:")
        assert result[2].path.startswith("C:")

    def test_sort_preserves_original(self):
        entries = [make_entry(pid=3), make_entry(pid=1), make_entry(pid=2)]
        original_order = [e.pid for e in entries]
        _ = HandleScanner.sort_entries(entries, "pid")
        assert [e.pid for e in entries] == original_order

    def test_sort_empty_list(self):
        result = HandleScanner.sort_entries([], "pid")
        assert result == []


# ---------------------------------------------------------------------------
# NT 路径转换测试
# ---------------------------------------------------------------------------
class TestNtToWin32:
    """测试 _nt_to_win32 方法"""

    def test_convert_harddisk_volume1(self):
        nt_path = r"\Device\HarddiskVolume1\Users\test.txt"
        result = HandleScanner._nt_to_win32(nt_path)
        assert result == r"C:\Users\test.txt"

    def test_convert_harddisk_volume2(self):
        nt_path = r"\Device\HarddiskVolume2\Projects\code.py"
        result = HandleScanner._nt_to_win32(nt_path)
        assert result == r"D:\Projects\code.py"

    def test_convert_harddisk_volume3(self):
        nt_path = r"\Device\HarddiskVolume3\Data\file.txt"
        result = HandleScanner._nt_to_win32(nt_path)
        assert result == r"E:\Data\file.txt"

    def test_case_insensitive(self):
        nt_path = r"\device\harddiskvolume1\test.txt"
        result = HandleScanner._nt_to_win32(nt_path)
        assert result == r"C:\test.txt"

    def test_unknown_volume_returns_original(self):
        nt_path = r"\Device\UnknownVolume\test.txt"
        result = HandleScanner._nt_to_win32(nt_path)
        assert result == nt_path


# ---------------------------------------------------------------------------
# 进程终止测试 (Mock)
# ---------------------------------------------------------------------------
class TestKillProcess:
    """测试 kill_process 方法 (使用 Mock)"""

    @patch("handle_monitor.OpenProcess")
    @patch("handle_monitor.TerminateProcess")
    @patch("handle_monitor.CloseHandle")
    def test_kill_success(self, mock_close, mock_terminate, mock_open):
        mock_open.return_value = 12345
        mock_terminate.return_value = True

        success, err = HandleScanner.kill_process(1234)

        assert success is True
        assert err == ""
        mock_open.assert_called_once()
        mock_terminate.assert_called_once()
        mock_close.assert_called_once()

    @patch("handle_monitor.OpenProcess")
    @patch("handle_monitor.TerminateProcess")
    @patch("handle_monitor.CloseHandle")
    def test_kill_failure_terminate(self, mock_close, mock_terminate, mock_open):
        mock_open.return_value = 12345
        mock_terminate.return_value = False

        success, err = HandleScanner.kill_process(1234)

        assert success is False
        assert len(err) > 0  # 有错误信息
        mock_close.assert_called_once()

    @patch("handle_monitor.OpenProcess", return_value=0)
    def test_kill_failure_open(self, mock_open):
        success, err = HandleScanner.kill_process(99999)

        assert success is False
        assert "无法打开进程" in err


# ---------------------------------------------------------------------------
# 进程存活检测测试 (Mock)
# ---------------------------------------------------------------------------
class TestIsProcessAlive:
    """测试 is_process_alive 方法 (使用 Mock)"""

    @patch("handle_monitor.OpenProcess")
    @patch("handle_monitor.GetExitCodeProcess")
    @patch("handle_monitor.CloseHandle")
    def test_process_alive(self, mock_close, mock_get_exit, mock_open):
        mock_open.return_value = 12345
        mock_get_exit.return_value = True

        # Mock the DWORD and byref behavior
        with patch("handle_monitor.ctypes.wintypes.DWORD") as mock_dword_class:
            mock_dword_instance = MagicMock()
            mock_dword_instance.value = 259  # STILL_ACTIVE
            mock_dword_class.return_value = mock_dword_instance

            with patch("handle_monitor.ctypes.byref", return_value=mock_dword_instance):
                result = HandleScanner.is_process_alive(1234)

        assert result is True
        mock_close.assert_called_once()

    @patch("handle_monitor.OpenProcess")
    @patch("handle_monitor.GetExitCodeProcess")
    @patch("handle_monitor.CloseHandle")
    def test_process_dead(self, mock_close, mock_get_exit, mock_open):
        mock_open.return_value = 12345
        mock_get_exit.return_value = True

        with patch("handle_monitor.ctypes.wintypes.DWORD") as mock_dword_class:
            mock_dword_instance = MagicMock()
            mock_dword_instance.value = 0  # Exit code
            mock_dword_class.return_value = mock_dword_instance

            with patch("handle_monitor.ctypes.byref", return_value=mock_dword_instance):
                result = HandleScanner.is_process_alive(1234)

        assert result is False
        mock_close.assert_called_once()

    @patch("handle_monitor.OpenProcess")
    def test_process_not_found(self, mock_open):
        mock_open.return_value = 0
        result = HandleScanner.is_process_alive(99999)
        assert result is False


# ---------------------------------------------------------------------------
# 快速刷新测试 (Mock)
# ---------------------------------------------------------------------------
class TestQuickRefresh:
    """测试 quick_refresh 方法"""

    @patch.object(HandleScanner, "is_process_alive")
    def test_quick_refresh_removes_dead_processes(self, mock_alive):
        scanner = HandleScanner()
        scanner.last_handles = [
            make_entry(pid=1000),
            make_entry(pid=2000),
            make_entry(pid=3000),
        ]

        # PID 1000 和 3000 存活，2000 已退出
        mock_alive.side_effect = lambda pid: pid in [1000, 3000]

        alive, removed_count = scanner.quick_refresh()

        assert len(alive) == 2
        assert removed_count == 1
        assert all(e.pid in [1000, 3000] for e in alive)

    @patch.object(HandleScanner, "is_process_alive")
    def test_quick_refresh_all_alive(self, mock_alive):
        scanner = HandleScanner()
        scanner.last_handles = [make_entry(pid=1000), make_entry(pid=2000)]
        mock_alive.return_value = True

        alive, removed_count = scanner.quick_refresh()

        assert len(alive) == 2
        assert removed_count == 0

    @patch.object(HandleScanner, "is_process_alive")
    def test_quick_refresh_all_dead(self, mock_alive):
        scanner = HandleScanner()
        scanner.last_handles = [make_entry(pid=1000), make_entry(pid=2000)]
        mock_alive.return_value = False

        alive, removed_count = scanner.quick_refresh()

        assert len(alive) == 0
        assert removed_count == 2


# ---------------------------------------------------------------------------
# 常见操作路径集成测试
# ---------------------------------------------------------------------------
class TestCommonOperationPaths:
    """测试常见操作路径"""

    def test_scan_filter_sort_workflow(self):
        """测试：扫描 → 过滤 → 排序"""
        # 模拟扫描结果
        entries = [
            make_entry(process_name="notepad.exe", pid=2000, path=r"C:\Docs\a.txt"),
            make_entry(process_name="explorer.exe", pid=1000, path=r"C:\Docs\b.txt"),
            make_entry(process_name="notepad++.exe", pid=3000, path=r"D:\Files\c.txt"),
        ]

        # 按进程名过滤
        filtered = HandleScanner.filter_entries(entries, "notepad")
        assert len(filtered) == 2

        # 按 PID 排序
        sorted_entries = HandleScanner.sort_entries(filtered, "pid", reverse=False)
        assert sorted_entries[0].pid == 2000
        assert sorted_entries[1].pid == 3000

    @patch.object(HandleScanner, "is_process_alive")
    def test_scan_refresh_filter_workflow(self, mock_alive):
        """测试：扫描 → 快速刷新 → 过滤"""
        scanner = HandleScanner()
        scanner.last_handles = [
            make_entry(process_name="app1.exe", pid=1000),
            make_entry(process_name="app2.exe", pid=2000),
            make_entry(process_name="app3.exe", pid=3000),
        ]

        # 快速刷新：PID 2000 已退出
        mock_alive.side_effect = lambda pid: pid != 2000
        alive, _ = scanner.quick_refresh()
        assert len(alive) == 2

        # 过滤
        filtered = HandleScanner.filter_entries(alive, "app1")
        assert len(filtered) == 1
        assert filtered[0].pid == 1000

    @patch("handle_monitor.OpenProcess")
    @patch("handle_monitor.TerminateProcess")
    @patch("handle_monitor.CloseHandle")
    def test_scan_kill_verify_removal(self, mock_close, mock_terminate, mock_open):
        """测试：扫描 → 结束进程 → 验证移除"""
        # 模拟扫描结果
        entries = [
            make_entry(process_name="app1.exe", pid=1000),
            make_entry(process_name="app2.exe", pid=2000),
            make_entry(process_name="app3.exe", pid=3000),
        ]

        # 模拟结束进程成功
        mock_open.return_value = 99999
        mock_terminate.return_value = True

        # 结束 PID 2000
        success, _ = HandleScanner.kill_process(2000)
        assert success is True

        # 从列表中移除
        killed_pid = 2000
        remaining = [e for e in entries if e.pid != killed_pid]
        assert len(remaining) == 2
        assert all(e.pid != 2000 for e in remaining)

    def test_complex_filter_scenario(self):
        """测试：复杂过滤场景（多关键词匹配）"""
        entries = [
            make_entry(process_name="notepad.exe", pid=1234, path=r"C:\Users\test\file.txt"),
            make_entry(process_name="explorer.exe", pid=5678, path=r"C:\Windows\system32"),
            make_entry(process_name="notepad++.exe", pid=9999, path=r"D:\Projects\code.py"),
        ]

        # 过滤 "notepad" - 匹配进程名
        result1 = HandleScanner.filter_entries(entries, "notepad")
        assert len(result1) == 2

        # 过滤 "1234" - 匹配 PID
        result2 = HandleScanner.filter_entries(entries, "1234")
        assert len(result2) == 1
        assert result2[0].process_name == "notepad.exe"

        # 过滤 "test" - 匹配路径
        result3 = HandleScanner.filter_entries(entries, "test")
        assert len(result3) == 1
        assert "Users\\test" in result3[0].path

    def test_sort_multiple_columns(self):
        """测试：多列排序"""
        entries = [
            make_entry(process_name="b.exe", pid=2000),
            make_entry(process_name="a.exe", pid=1000),
            make_entry(process_name="c.exe", pid=3000),
        ]

        # 按进程名排序
        sorted1 = HandleScanner.sort_entries(entries, "process")
        assert sorted1[0].process_name == "a.exe"

        # 按 PID 排序
        sorted2 = HandleScanner.sort_entries(entries, "pid")
        assert sorted2[0].pid == 1000

        # 反向排序
        sorted3 = HandleScanner.sort_entries(entries, "pid", reverse=True)
        assert sorted3[0].pid == 3000


# ---------------------------------------------------------------------------
# HandleEntry 数据类测试
# ---------------------------------------------------------------------------
class TestHandleEntry:
    """测试 HandleEntry 数据类"""

    def test_entry_creation(self):
        entry = HandleEntry("test.exe", 1234, "File", "ABC", r"C:\test.txt")
        assert entry.process_name == "test.exe"
        assert entry.pid == 1234
        assert entry.handle_type == "File"
        assert entry.handle_value == "ABC"
        assert entry.path == r"C:\test.txt"
        assert entry.first_seen is not None
        assert entry.last_seen is not None

    def test_entry_repr(self):
        entry = HandleEntry("test.exe", 1234, "File", "ABC", r"C:\test.txt")
        repr_str = repr(entry)
        assert "test.exe" in repr_str
        assert "1234" in repr_str
        assert r"C:\test.txt" in repr_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
