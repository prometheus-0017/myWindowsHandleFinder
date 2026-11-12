"""
文件句柄监控工具 (File Handle Monitor)
扫描指定文件夹下的文件句柄占用情况，支持自动刷新、快速刷新、搜索和结束占用进程。
依赖: pip install pywin32
需要下载 Sysinternals handle.exe 并放置在 PATH 中或程序同目录下。
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import re
import threading
import time
import ctypes
import ctypes.wintypes
import queue
from datetime import datetime

# ---------------------------------------------------------------------------
# Win32 API 常量与类型
# ---------------------------------------------------------------------------
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
STILL_ACTIVE = 259

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.restype = ctypes.wintypes.HANDLE
OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = ctypes.wintypes.BOOL
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

GetExitCodeProcess = kernel32.GetExitCodeProcess
GetExitCodeProcess.restype = ctypes.wintypes.BOOL
GetExitCodeProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD)]

TerminateProcess = kernel32.TerminateProcess
TerminateProcess.restype = ctypes.wintypes.BOOL
TerminateProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.UINT]


# ---------------------------------------------------------------------------
# 句柄数据类
# ---------------------------------------------------------------------------
class HandleEntry:
    """单条句柄记录"""

    def __init__(self, process_name, pid, handle_type, handle_value, path):
        self.process_name = process_name
        self.pid = pid
        self.handle_type = handle_type
        self.handle_value = handle_value
        self.path = path
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()

    def __repr__(self):
        return f"{self.process_name}({self.pid}) -> {self.path}"


# ---------------------------------------------------------------------------
# 句柄扫描器
# ---------------------------------------------------------------------------
class HandleScanner:
    """使用 handle.exe 扫描文件句柄"""

    def __init__(self):
        self.handle_exe = self._find_handle_exe()
        self.last_handles: list[HandleEntry] = []

    # ---- 查找 handle.exe ----
    def _find_handle_exe(self) -> str | None:
        # 1) 程序自身所在目录
        app_dir = os.path.dirname(os.path.abspath(__file__))
        local_path = os.path.join(app_dir, "handle.exe")
        if os.path.isfile(local_path):
            return local_path

        # 2) 系统 PATH
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            candidate = os.path.join(directory, "handle.exe")
            if os.path.isfile(candidate):
                return candidate

        return None

    @property
    def available(self) -> bool:
        return self.handle_exe is not None

    # ---- 核心扫描 ----
    def scan(self, folder: str, progress_cb=None) -> list[HandleEntry]:
        """扫描所有文件句柄并过滤到指定文件夹"""
        if not self.available:
            raise RuntimeError("handle.exe 未找到")

        folder_normalized = os.path.normpath(folder).lower()
        entries: list[HandleEntry] = []
        seen: set[tuple] = set()

        if progress_cb:
            progress_cb("正在启动 handle.exe …")

        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            proc = subprocess.Popen(
                [self.handle_exe, "-accepteula", "-a", "-u"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                startupinfo=startupinfo,
            )

            current_proc = None
            current_pid = None
            line_count = 0

            for line in proc.stdout:
                line = line.rstrip()
                line_count += 1

                # 进程头:  "explorer.exe pid: 4512 DESKTOP-XX\\user"
                proc_match = re.match(r"^(\S+)\s+pid:\s+(\d+)", line)
                if proc_match:
                    current_proc = proc_match.group(1)
                    current_pid = int(proc_match.group(2))
                    continue

                # 句柄行:  "  45C: File  \Device\HarddiskVolume3\Users\..."
                handle_match = re.match(
                    r"^\s+([0-9A-Fa-f]+):\s+(\S+)\s+(.+)$", line
                )
                if handle_match and current_proc:
                    h_value = handle_match.group(1)
                    h_type = handle_match.group(2)
                    h_path = handle_match.group(3).strip()

                    if h_type == "File" and h_path:
                        # 将 NT 路径转为 Win32 路径用于比较
                        win32_path = self._nt_to_win32(h_path)
                        path_lower = win32_path.lower()

                        if folder_normalized in path_lower:
                            key = (current_proc, current_pid, h_value, h_path)
                            if key not in seen:
                                seen.add(key)
                                entries.append(
                                    HandleEntry(
                                        current_proc,
                                        current_pid,
                                        h_type,
                                        h_value,
                                        win32_path,
                                    )
                                )

                if progress_cb and line_count % 5000 == 0:
                    progress_cb(f"已扫描 {line_count} 行, 找到 {len(entries)} 个匹配句柄 …")

            proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError("handle.exe 执行超时")
        except Exception as exc:
            raise RuntimeError(f"扫描出错: {exc}")

        self.last_handles = entries
        return entries

    @staticmethod
    def _nt_to_win32(nt_path: str) -> str:
        """尝试将 NT 设备路径转换为 Win32 路径"""
        _DEVICE_MAP = {
            "\\device\\harddiskvolume1": "C:",
            "\\device\\harddiskvolume2": "D:",
            "\\device\\harddiskvolume3": "E:",
            "\\device\\harddiskvolume4": "F:",
            "\\device\\harddiskvolume5": "G:",
            "\\device\\harddiskvolume6": "H:",
        }
        lower = nt_path.lower()
        for nt_prefix, drive in _DEVICE_MAP.items():
            if lower.startswith(nt_prefix):
                return drive + nt_path[len(nt_prefix):]
        # 常见映射
        if lower.startswith("\\device\\harddiskvolume"):
            # 尝试通过 GetLogicalDriveStrings 动态映射
            return nt_path
        return nt_path

    # ---- 进程存活检测 ----
    @staticmethod
    def is_process_alive(pid: int) -> bool:
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return False
        try:
            code = ctypes.wintypes.DWORD()
            if GetExitCodeProcess(h, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return False
        finally:
            CloseHandle(h)

    # ---- 快速刷新: 剔除已退出进程 ----
    def quick_refresh(self) -> tuple[list[HandleEntry], int]:
        alive_entries = []
        removed_pids: set[int] = set()
        for e in self.last_handles:
            if self.is_process_alive(e.pid):
                alive_entries.append(e)
            else:
                removed_pids.add(e.pid)
        self.last_handles = alive_entries
        return alive_entries, len(removed_pids)

    # ---- 结束进程 ----
    @staticmethod
    def kill_process(pid: int) -> tuple[bool, str]:
        h = OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h:
            err = ctypes.get_last_error()
            return False, f"无法打开进程: {ctypes.FormatError(err)}"
        try:
            if TerminateProcess(h, 1):
                return True, ""
            err = ctypes.get_last_error()
            return False, f"终止失败: {ctypes.FormatError(err)}"
        finally:
            CloseHandle(h)

    # ---- 过滤句柄 ----
    @staticmethod
    def filter_entries(entries: list[HandleEntry], keyword: str) -> list[HandleEntry]:
        """按关键词过滤句柄列表"""
        if not keyword:
            return entries
        keyword_lower = keyword.lower()
        result = []
        for e in entries:
            haystack = f"{e.process_name} {e.pid} {e.handle_type} {e.handle_value} {e.path}".lower()
            if keyword_lower in haystack:
                result.append(e)
        return result

    # ---- 排序句柄 ----
    _COLUMN_ATTR_MAP = {
        "process": "process_name",
        "pid": "pid",
        "type": "handle_type",
        "handle": "handle_value",
        "path": "path",
    }

    @staticmethod
    def sort_entries(
        entries: list[HandleEntry], column: str, reverse: bool = False
    ) -> list[HandleEntry]:
        """按指定列排序句柄列表"""
        attr = HandleScanner._COLUMN_ATTR_MAP.get(column, column)
        sorted_entries = sorted(
            entries,
            key=lambda e: getattr(e, attr, ""),
            reverse=reverse,
        )
        return sorted_entries


# ---------------------------------------------------------------------------
# GUI 应用
# ---------------------------------------------------------------------------
class HandleMonitorApp:
    REFRESH_INTERVALS = [5, 10, 15, 30, 60, 120]

    def __init__(self, root: tk.Tk):
        self.root = root
        admin_tag = " [管理员]" if is_admin() else ""
        self.root.title(f"文件句柄监控工具{admin_tag}")
        self.root.geometry("1280x800")
        self.root.minsize(960, 600)

        # 尝试设置窗口图标 (忽略错误)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # ---- 状态变量 ----
        self.scanner = HandleScanner()
        self.all_entries: list[HandleEntry] = []
        self.is_scanning = False
        self.auto_refresh_var = tk.BooleanVar(value=False)
        self.refresh_interval_var = tk.StringVar(value="10")
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="就绪")
        self._scan_queue: queue.Queue = queue.Queue()
        self._after_id = None

        self._build_ui()
        self._poll_queue()

    # ======================== UI 构建 ========================
    def _build_ui(self):
        style = ttk.Style()
        style.configure("Treeview", rowheight=22)
        style.configure("TLabelframe.Label", font=("Microsoft YaHei UI", 9))

        main = ttk.Frame(self.root, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        # ---------- 文件夹选择 ----------
        folder_frame = ttk.LabelFrame(main, text="目标文件夹", padding=4)
        folder_frame.pack(fill=tk.X, pady=(0, 4))

        self.folder_var = tk.StringVar()
        ttk.Entry(folder_frame, textvariable=self.folder_var, font=("Consolas", 10)).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4)
        )
        ttk.Button(folder_frame, text="浏览 …", command=self._browse).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        self.scan_btn = ttk.Button(folder_frame, text="开始扫描", command=self._toggle_scan)
        self.scan_btn.pack(side=tk.LEFT)

        # ---------- 控制栏 ----------
        ctrl = ttk.Frame(main, padding=4)
        ctrl.pack(fill=tk.X, pady=(0, 4))

        # 自动刷新
        ttk.Checkbutton(ctrl, text="自动刷新", variable=self.auto_refresh_var,
                        command=self._toggle_auto_refresh).pack(side=tk.LEFT)
        ttk.Label(ctrl, text="  间隔(秒): ").pack(side=tk.LEFT)
        interval_cb = ttk.Combobox(ctrl, textvariable=self.refresh_interval_var,
                                   values=[str(i) for i in self.REFRESH_INTERVALS],
                                   width=4, state="readonly")
        interval_cb.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Separator(ctrl, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)

        # 快速刷新
        ttk.Button(ctrl, text="快速刷新 (清除已退出进程)",
                   command=self._quick_refresh).pack(side=tk.LEFT, padx=(0, 4))

        # 结束所选进程
        ttk.Button(ctrl, text="结束所选进程",
                   command=self._kill_selected).pack(side=tk.LEFT, padx=(0, 4))

        # 清空
        ttk.Button(ctrl, text="清空结果", command=self._clear).pack(side=tk.LEFT, padx=(0, 4))

        # 统计
        self.count_label = ttk.Label(ctrl, text="共 0 条句柄")
        self.count_label.pack(side=tk.RIGHT)

        # ---------- 搜索栏 ----------
        search = ttk.LabelFrame(main, text="搜索 / 过滤", padding=4)
        search.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(search, text="关键词:").pack(side=tk.LEFT)
        search_entry = ttk.Entry(search, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=4)
        self.search_var.trace_add("write", lambda *_: self._apply_filters)

        ttk.Button(search, text="清空搜索",
                   command=lambda: self.search_var.set("")).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(search, text="定位下一个",
                   command=self._next_match).pack(side=tk.LEFT)

        # ---------- 结果表格 ----------
        tree_frame = ttk.Frame(main)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        cols = ("process", "pid", "type", "handle", "path")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                 selectmode="extended")

        self.tree.heading("process", text="进程名",
                          command=lambda: self._sort_col("process"))
        self.tree.heading("pid", text="PID",
                          command=lambda: self._sort_col("pid"))
        self.tree.heading("type", text="类型",
                          command=lambda: self._sort_col("type"))
        self.tree.heading("handle", text="句柄值",
                          command=lambda: self._sort_col("handle"))
        self.tree.heading("path", text="文件路径",
                          command=lambda: self._sort_col("path"))

        self.tree.column("process", width=150, minwidth=80)
        self.tree.column("pid", width=70, minwidth=50, anchor=tk.CENTER)
        self.tree.column("type", width=60, minwidth=50, anchor=tk.CENTER)
        self.tree.column("handle", width=80, minwidth=60, anchor=tk.CENTER)
        self.tree.column("path", width=700, minwidth=200)

        self.tree.bind("<Double-1>", self._on_double_click)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # ---------- 状态栏 ----------
        status = ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN,
                           anchor=tk.W, padding=(4, 2))
        status.pack(fill=tk.X)

        # 初始提示
        if not self.scanner.available:
            self.status_var.set(
                "⚠ handle.exe 未找到！请将 Sysinternals handle.exe 放入程序目录或系统 PATH 中。"
                "  下载地址: https://learn.microsoft.com/sysinternals/downloads/handle"
            )

    # ======================== 文件夹 / 扫描 ========================
    def _browse(self):
        d = filedialog.askdirectory(title="选择要监控的文件夹")
        if d:
            self.folder_var.set(d)

    def _toggle_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.scan_btn.config(text="开始扫描")
            self.status_var.set("扫描已取消")
        else:
            self._start_scan()

    def _start_scan(self):
        folder = self.folder_var.get().strip()
        if not folder:
            messagebox.showwarning("提示", "请先选择或输入文件夹路径")
            return
        if not os.path.isdir(folder):
            messagebox.showerror("错误", f"文件夹不存在:\n{folder}")
            return
        if not self.scanner.available:
            messagebox.showerror(
                "缺少 handle.exe",
                "未找到 Sysinternals handle.exe。\n\n"
                "请下载 handle.exe 并放到程序所在目录，或加入系统 PATH。\n"
                "下载地址:\nhttps://learn.microsoft.com/sysinternals/downloads/handle",
            )
            return

        self.is_scanning = True
        self.scan_btn.config(text="停止扫描")
        self.status_var.set("正在扫描 …")

        def _worker():
            try:
                result = self.scanner.scan(
                    folder,
                    progress_cb=lambda msg: self._scan_queue.put(("progress", msg)),
                )
                self._scan_queue.put(("done", result))
            except Exception as exc:
                self._scan_queue.put(("error", str(exc)))

        threading.Thread(target=_worker, daemon=True).start()

    def _poll_queue(self):
        """主循环中轮询后台扫描消息"""
        try:
            while True:
                msg_type, payload = self._scan_queue.get_nowait()
                if msg_type == "progress":
                    self.status_var.set(payload)
                elif msg_type == "done":
                    self.is_scanning = False
                    self.scan_btn.config(text="开始扫描")
                    self.all_entries = payload
                    self._apply_filters()
                    elapsed = (
                        (payload[0].last_seen - payload[0].first_seen).total_seconds()
                        if payload else 0
                    )
                    self.status_var.set(
                        f"扫描完成 — 共 {len(payload)} 个句柄  ({len(set(e.pid for e in payload))} 个进程)"
                    )
                elif msg_type == "error":
                    self.is_scanning = False
                    self.scan_btn.config(text="开始扫描")
                    self.status_var.set(f"扫描出错: {payload}")
                    messagebox.showerror("扫描错误", payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    # ======================== 快速刷新 ========================
    def _quick_refresh(self):
        if not self.all_entries:
            messagebox.showinfo("提示", "没有可刷新的句柄数据，请先执行扫描")
            return

        self.status_var.set("正在检查进程状态 …")
        self.root.update_idletasks()

        alive, removed_count = self.scanner.quick_refresh()
        self.all_entries = alive
        self._apply_filters()
        self.status_var.set(
            f"快速刷新完成 — 移除了 {removed_count} 个已退出进程, "
            f"剩余 {len(alive)} 个句柄"
        )

    # ======================== 结束所选进程 ========================
    def _kill_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择要结束进程的句柄行 (可按 Ctrl/Shift 多选)")
            return

        # 所选行对应的进程去重
        targets: dict[int, str] = {}
        for item in sel:
            vals = self.tree.item(item, "values")
            targets.setdefault(int(vals[1]), str(vals[0]))

        name_list = "\n".join(f"  {name}  (PID {pid})" for pid, name in targets.items())
        if not messagebox.askyesno(
            "确认结束进程",
            f"确定要强制结束以下 {len(targets)} 个进程吗?\n\n{name_list}\n\n"
            "进程将被强制终止, 未保存的数据可能丢失!",
        ):
            return

        killed: set[int] = set()
        failed: list[str] = []
        for pid, name in targets.items():
            ok, err = HandleScanner.kill_process(pid)
            if ok:
                killed.add(pid)
            else:
                failed.append(f"{name} (PID {pid}): {err}")

        if killed:
            self.all_entries = [e for e in self.all_entries if e.pid not in killed]
            self.scanner.last_handles = self.all_entries
            self._apply_filters()

        msg = f"已结束 {len(killed)} 个进程"
        if failed:
            msg += f", 失败 {len(failed)} 个"
            messagebox.showwarning("结束进程", "\n".join(failed))
        self.status_var.set(msg)

    # ======================== 自动刷新 ========================
    def _toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            self._schedule_auto_refresh()
        else:
            if self._after_id is not None:
                self.root.after_cancel(self._after_id)
                self._after_id = None

    def _schedule_auto_refresh(self):
        if not self.auto_refresh_var.get():
            return
        if not self.is_scanning and self.folder_var.get().strip():
            self._start_scan()
        secs = int(self.refresh_interval_var.get() or 10)
        self._after_id = self.root.after(secs * 1000, self._schedule_auto_refresh)

    # ======================== 过滤 / 搜索 ========================
    def _apply_filters(self, *_):
        keyword = self.search_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())

        filtered = HandleScanner.filter_entries(self.all_entries, keyword)
        for e in filtered:
            self.tree.insert(
                "", tk.END,
                values=(e.process_name, e.pid, e.handle_type, e.handle_value, e.path),
            )

        self.count_label.config(text=f"共 {len(filtered)} 条句柄")

    def _next_match(self):
        """滚动到下一个匹配项"""
        keyword = self.search_var.get().strip().lower()
        if not keyword:
            return
        children = self.tree.get_children()
        if not children:
            return

        sel = self.tree.selection()
        idx = 0
        if sel:
            try:
                cur = children.index(sel[0])
                idx = cur + 1
            except (ValueError, IndexError):
                idx = 0

        total = len(children)
        for i in range(total):
            item = children[(idx + i) % total]
            vals = self.tree.item(item, "values")
            if any(keyword in str(v).lower() for v in vals):
                self.tree.selection_set(item)
                self.tree.see(item)
                return

        messagebox.showinfo("搜索", "未找到更多匹配项")

    # ======================== 排序 ========================
    def _sort_col(self, col: str, reverse=False):
        self.all_entries = HandleScanner.sort_entries(self.all_entries, col, reverse)
        self._apply_filters()
        self.tree.heading(col, command=lambda: self._sort_col(col, not reverse))

    # ======================== 其他 ========================
    def _on_double_click(self, event):
        """双击复制文件路径"""
        item = self.tree.selection()
        if not item:
            return
        path = self.tree.item(item[0], "values")[4]
        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        self.status_var.set(f"已复制路径: {path}")

    def _clear(self):
        self.all_entries = []
        self.scanner.last_handles = []
        self.tree.delete(*self.tree.get_children())
        self.search_var.set("")
        self.count_label.config(text="共 0 条句柄")
        self.status_var.set("已清空")


# ---------------------------------------------------------------------------
# 管理员权限检测与提权
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def elevate_and_restart():
    """以管理员权限重新启动本程序"""
    import sys
    script = os.path.abspath(sys.argv[0])
    params = " ".join(sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
    except Exception:
        pass
    sys.exit(0)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main():
    root = tk.Tk()
    # 高 DPI 支持
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    # 检测管理员权限
    if not is_admin():
        result = messagebox.askyesno(
            "需要管理员权限",
            "扫描文件句柄需要管理员权限。\n"
            "是否以管理员身份重新启动？\n\n"
            "选择「否」将以普通权限运行（部分句柄可能无法读取）。",
        )
        if result:
            root.destroy()
            elevate_and_restart()
            return

    app = HandleMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
