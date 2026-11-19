#!/usr/bin/env python3
"""ShieldCore desktop front-end; local polling monitor, not OS-level real-time protection."""
import os, queue, subprocess, sys, threading, time, uuid
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from shieldcore import DATA_DIR

HERE = Path(__file__).resolve().parent
ENGINE = HERE / "shieldcore.py"

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("ShieldCore | Защита и проверка")
        self.root.geometry("850x590")
        self.root.minsize(680, 470)
        self.q = queue.Queue(); self.jobs = queue.Queue(maxsize=128)
        self.monitor_on = False; self.snapshot = {}
        self.active_cancel = None
        self.target = tk.StringVar(); self.quarantine = tk.BooleanVar(value=False)
        self._ui(); self.root.after(150, self.drain)
        threading.Thread(target=self.worker, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _ui(self):
        root=self.root
        root.configure(bg="#f3f6fa")
        style=ttk.Style(root)
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure("TButton",font=("Segoe UI",10),padding=(10,6))
        style.configure("Accent.TButton",font=("Segoe UI",10,"bold"),padding=(12,7),foreground="white",background="#1769aa")
        style.map("Accent.TButton",background=[("active","#12558a")])
        style.configure("TFrame",background="#f3f6fa")
        style.configure("Card.TFrame",background="white")
        style.configure("TLabel",background="#f3f6fa",font=("Segoe UI",10))
        style.configure("Title.TLabel",font=("Segoe UI",24,"bold"),foreground="#15334b")
        style.configure("Muted.TLabel",foreground="#526575")
        header=ttk.Frame(root); header.pack(fill="x",padx=22,pady=(18,10))
        ttk.Label(header,text="ShieldCore",style="Title.TLabel").pack(anchor="w")
        ttk.Label(header,text="Локальная проверка • база SQLite • карантин",style="Muted.TLabel").pack(anchor="w")
        card=ttk.Frame(root,style="Card.TFrame",padding=14); card.pack(fill="x",padx=20,pady=5)
        ttk.Label(card,text="Файл или папка для проверки / наблюдения:",style="Muted.TLabel").pack(anchor="w")
        row=ttk.Frame(card,style="Card.TFrame"); row.pack(fill="x",pady=7)
        self.entry=ttk.Entry(row,textvariable=self.target); self.entry.pack(side="left",fill="x",expand=True)
        ttk.Button(row,text="Обзор…",command=self.browse).pack(side="left",padx=(8,0))
        actions=ttk.Frame(card,style="Card.TFrame"); actions.pack(fill="x",pady=(2,0))
        ttk.Button(actions,text="Сканировать",style="Accent.TButton",command=self.scan).pack(side="left")
        self.cancel_btn=ttk.Button(actions,text="Отменить сканирование",command=self.cancel_scan,state="disabled"); self.cancel_btn.pack(side="left",padx=7)
        self.monbtn=ttk.Button(actions,text="Мониторинг папки",command=self.toggle_monitor); self.monbtn.pack(side="left",padx=7)
        ttk.Checkbutton(actions,text="Карантин (переместить находки)",variable=self.quarantine).pack(side="left",padx=4)
        controls=ttk.Frame(card,style="Card.TFrame"); controls.pack(fill="x",pady=(8,0))
        ttk.Label(controls,text="Интервал мониторинга, сек:",style="Muted.TLabel").pack(side="left")
        self.interval_var=tk.IntVar(value=5)
        ttk.Spinbox(controls,from_=2,to=60,width=5,textvariable=self.interval_var).pack(side="left",padx=6)
        ttk.Button(controls,text="Добавить исключение папки…",command=self.add_exclusion).pack(side="left",padx=(12,5))
        ttk.Button(controls,text="Показать исключения",command=self.list_exclusions).pack(side="left")
        ttk.Button(controls,text="Убрать исключение…",command=self.remove_exclusion).pack(side="left",padx=5)
        tools=ttk.Frame(root); tools.pack(fill="x",padx=20,pady=9)
        ttk.Button(tools,text="Журнал / находки",command=self.report).pack(side="left")
        ttk.Button(tools,text="Восстановить из карантина",command=self.restore_item).pack(side="left",padx=6)
        ttk.Button(tools,text="Добавить SHA-256",command=self.add_hash).pack(side="left",padx=6)
        ttk.Button(tools,text="Импорт JSON-базы…",command=self.import_db).pack(side="left",padx=6)
        ttk.Button(tools,text="Состояние базы",command=lambda:self.run_engine(["db-info"])).pack(side="left",padx=6)
        tools2=ttk.Frame(root); tools2.pack(fill="x",padx=20,pady=(0,7))
        ttk.Button(tools2,text="Проверить Microsoft Defender…",command=self.defender_scan).pack(side="left")
        ttk.Button(tools2,text="Статус Microsoft Defender",command=lambda:self.run_engine(["defender-status"])).pack(side="left",padx=6)
        self.status=tk.StringVar(value="Готово — выберите объект проверки.")
        ttk.Label(root,textvariable=self.status,anchor="w",style="Muted.TLabel").pack(fill="x",padx=22,pady=(2,3))
        self.progress=ttk.Progressbar(root,mode="indeterminate",length=300)
        self.progress.pack(fill="x",padx=22,pady=(0,8))
        self.out=scrolledtext.ScrolledText(root,wrap="word",font=("Consolas",10),state="disabled",height=13,
                                           background="#101b2a",foreground="#e7eff8",insertbackground="white",borderwidth=0)
        self.out.pack(fill="both",expand=True,padx=20,pady=(0,9))
        ttk.Label(root,text="Наблюдение — периодический опрос, не блокирует запуск файлов. Оставьте Microsoft Defender включённым.",
                  foreground="#8b4a00",wraplength=820,justify="left").pack(anchor="w",padx=22,pady=(0,12))
        self.log("Готово. Выберите файл или папку; результаты и причины пропуска будут показаны здесь.")
    def log(self,s):
        self.out.configure(state="normal"); self.out.insert("end",time.strftime("%H:%M:%S  ")+str(s)+"\n"); self.out.see("end"); self.out.configure(state="disabled")
    def browse(self):
        p=filedialog.askdirectory(title="Выберите папку")
        if not p: p=filedialog.askopenfilename(title="Или выберите файл")
        if p: self.target.set(p)
    def run_engine(self,args):
        args=list(args); cancel_path=None
        if args and args[0]=="scan":
            DATA_DIR.mkdir(parents=True,exist_ok=True)
            cancel_path=DATA_DIR/("cancel-"+uuid.uuid4().hex)
            args += ["--cancel-file",str(cancel_path)]
        try:
            self.jobs.put_nowait((args,cancel_path))
            self.status.set("Задача добавлена в очередь…")
        except queue.Full:
            self.log("Очередь задач заполнена; дождитесь завершения текущих проверок.")
    def worker(self):
        while True:
            args,cancel_path = self.jobs.get()
            self.active_cancel=cancel_path
            self.q.put(("job-start", "Выполняю: " + args[0]))
            try:
                proc=subprocess.Popen([sys.executable,"-u",str(ENGINE)]+args,cwd=HERE,text=True,
                                      stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=1)
                for line in proc.stdout:
                    line=line.rstrip()
                    if line.startswith("PROGRESS "):
                        bits=line.split()
                        self.q.put(("progress",f"Проверено файлов: {bits[1]} • находок: {bits[2]}"))
                    elif line:
                        self.q.put(("log",line))
                code=proc.wait(timeout=3600)
                self.q.put(("status","Завершено." if code==0 else "Завершено с ошибкой; смотрите журнал."))
            except Exception as e:
                self.q.put(("log","Ошибка запуска: "+str(e))); self.q.put(("status","Ошибка."))
            finally:
                if cancel_path:
                    try: cancel_path.unlink(missing_ok=True)
                    except OSError: pass
                self.active_cancel=None
                self.q.put(("job-end",""))
                self.jobs.task_done()
    def cancel_scan(self):
        if self.active_cancel:
            try:
                self.active_cancel.parent.mkdir(parents=True,exist_ok=True)
                self.active_cancel.write_text("cancel",encoding="ascii")
                self.status.set("Отмена запрошена — завершу текущий файл и остановлюсь.")
            except OSError as e:
                self.log("Не удалось запросить отмену: "+str(e))
        else:
            self.log("Сейчас нет активного сканирования для отмены.")
    def add_exclusion(self):
        path=filedialog.askdirectory(title="Выберите папку, которую исключить из сканирования")
        if path:self.run_engine(["exclude-add",path])
    def list_exclusions(self): self.run_engine(["exclude-list"])
    def defender_scan(self):
        path=self.target.get().strip()
        if not path or not Path(path).exists():
            path=filedialog.askdirectory(title="Выберите папку для Microsoft Defender")
            if not path:path=filedialog.askopenfilename(title="Или выберите файл")
        if path and messagebox.askyesno("Microsoft Defender", "Передать выбранный путь встроенному Microsoft Defender для проверки? Стандартная защита Windows должна оставаться включённой."):
            self.run_engine(["defender-scan",path])
    def import_db(self):
        path=filedialog.askopenfilename(title="Выберите локальный JSON-feed",filetypes=[("JSON feed","*.json"),("Все файлы","*.*")])
        if path and messagebox.askyesno("Импорт базы", "Импортировать проверенный вами локальный feed? Не импортируйте неизвестные источники."):
            self.run_engine(["import-db",path])
    def remove_exclusion(self):
        import tkinter.simpledialog as sd
        path=sd.askstring("Убрать исключение", "Вставьте полный путь из списка исключений:")
        if path:self.run_engine(["exclude-remove",path.strip()])
    def close(self):
        self.monitor_on=False
        self.root.destroy()
    def scan(self):
        p=self.target.get().strip()
        if not p or not Path(p).exists(): messagebox.showinfo("ShieldCore","Выберите существующий файл или папку."); return
        args=["scan",p]
        if self.quarantine.get(): args.append("--quarantine")
        self.run_engine(args)
    def report(self): self.run_engine(["report"])
    def restore_item(self):
        import tkinter.simpledialog as sd
        qid=sd.askstring("Восстановление", "Введите ID элемента из раздела карантина в отчёте:")
        if qid:
            if messagebox.askyesno("Подтверждение", "Файл будет восстановлен по исходному пути, если он свободен. Продолжить?"):
                self.run_engine(["restore", qid.strip()])
    def add_hash(self):
        p=filedialog.askopenfilename(title="Выберите файл для добавления его SHA-256")
        if not p:return
        import tkinter.simpledialog as sd
        name=sd.askstring("Имя сигнатуры","Введите понятное имя этой сигнатуры:")
        if name:self.run_engine(["add-hash",p,"--name",name])
    def toggle_monitor(self):
        if self.monitor_on:
            self.monitor_on=False; self.monbtn.configure(text="Запустить мониторинг папки"); self.status.set("Мониторинг остановлен."); self.log("Мониторинг остановлен."); return
        p=Path(self.target.get().strip()).expanduser()
        if not p.is_dir(): messagebox.showinfo("ShieldCore","Для мониторинга выберите существующую папку."); return
        self.monitor_on=True; self.monbtn.configure(text="Остановить мониторинг")
        self.monitor_quarantine=self.quarantine.get()
        try: self.monitor_interval=max(2,min(60,int(self.interval_var.get())))
        except (ValueError,tk.TclError): self.monitor_interval=5
        self.status.set(f"Мониторинг папки активен (опрос каждые {self.monitor_interval} сек).")
        self.log("Первичный проход: запоминаю текущее состояние; новые/изменённые файлы будут отправляться на сканирование.")
        threading.Thread(target=self.monitor,args=(p.resolve(),),daemon=True).start()
    def monitor(self,root):
        first=True
        while self.monitor_on:
            current={}
            try:
                for p in root.rglob('*'):
                    if p.is_symlink() or not p.is_file() or HERE in p.parents: continue
                    try: current[str(p)]=(p.stat().st_mtime_ns,p.stat().st_size)
                    except OSError: pass
                if not first:
                    changed=[p for p,v in current.items() if self.snapshot.get(p)!=v]
                    for p in changed:
                        self.q.put(("log","Изменение: "+p+" — запускаю сканирование"))
                        args=["scan",p]
                        if self.monitor_quarantine: args.append("--quarantine")
                        self.run_engine(args)
                self.snapshot=current; first=False
            except Exception as e:self.q.put(("log","Ошибка мониторинга: "+str(e)))
            for _ in range(self.monitor_interval):
                if not self.monitor_on: break
                time.sleep(1)
    def drain(self):
        try:
            while True:
                kind,text=self.q.get_nowait()
                if kind=="log":self.log(text)
                elif kind=="job-start":
                    self.status.set(text); self.progress.start(12); self.cancel_btn.configure(state="normal")
                elif kind=="progress": self.status.set(text)
                elif kind=="job-end":
                    self.progress.stop(); self.cancel_btn.configure(state="disabled")
                else:self.status.set(text)
        except queue.Empty:pass
        self.root.after(150,self.drain)

if __name__=='__main__':
    r=tk.Tk(); app=App(r); r.mainloop()
