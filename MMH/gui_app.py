import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from test_hastad_attack import RSAModule, chinese_remainder_theorem, iroot_e, hastad_broadcast_attack, generate_rsa_components
from functools import reduce

class HastadApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mô phỏng tấn công Håstad với số mũ e nhỏ")
        self.root.geometry("1050x750")
        self.root.configure(bg="#1e222b")
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TNotebook", background="#1e222b", borderwidth=0)
        self.style.configure("TNotebook.Tab", font=("Helvetica", 13, "bold"), padding=[15, 8], background="#2d3139", foreground="#a6acb9")
        self.style.map("TNotebook.Tab", background=[("selected", "#4b5263")], foreground=[("selected", "#ffffff")])

        self.rsa_system = RSAModule(key_size=128)
        self._create_widgets()

    def _create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=15)
        
        self.tab_rsa = tk.Frame(self.notebook, bg="#21252b")
        self.tab_hastad = tk.Frame(self.notebook, bg="#21252b")
        self.tab_visual = tk.Frame(self.notebook, bg="#21252b")
       
        self.notebook.add(self.tab_rsa, text=" 1. Sinh Khóa / Mã Hóa ")
        self.notebook.add(self.tab_hastad, text=" 2. Tấn công Håstad ")
        self.notebook.add(self.tab_visual, text=" 3. Trực quan hóa điều kiện ")

        self._setup_tab_rsa()
        self._setup_tab_hastad()
        self._setup_tab_visual()
        
    def _setup_tab_rsa(self):
        frame_top = tk.LabelFrame(self.tab_rsa, text=" Các thông số cần thiết ", padx=15, pady=15, bg="#21252b", fg="#61afef", font=("Helvetica", 14, "bold"))
        frame_top.pack(fill="x", padx=15, pady=10)
        
        tk.Label(frame_top, text="Số mũ e:", bg="#21252b", fg="#abb2bf", font=("Helvetica", 13, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.rsa_e = tk.Entry(frame_top, width=10, font=("Consolas", 14), bg="#282c34", fg="#98c379", insertbackground="white", bd=2)
        self.rsa_e.insert(0, "3")
        self.rsa_e.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        tk.Label(frame_top, text="Bản rõ m (nhỏ):", bg="#21252b", fg="#abb2bf", font=("Helvetica", 13, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.rsa_msg = tk.Entry(frame_top, width=65, font=("Consolas", 14), bg="#282c34", fg="#abb2bf", insertbackground="white", bd=2)
        self.rsa_msg.insert(0, "")
        self.rsa_msg.grid(row=1, column=1, padx=10, pady=5, sticky="w")
      
        frame_btn = tk.Frame(self.tab_rsa, bg="#21252b")
        frame_btn.pack(fill="x", padx=15, pady=5)
        
        btn = tk.Button(frame_btn, text="Sinh khóa & Mã hóa", command=self.run_rsa_standard, font=("Helvetica", 13, "bold"), bg="#98c379", fg="#1e222b", activebackground="#a3e08a", bd=0, padx=15, pady=6)
        btn.pack(side="left", padx=5)
        
        self.rsa_log = scrolledtext.ScrolledText(self.tab_rsa, wrap=tk.WORD, font=("Consolas", 13), bg="#282c34", fg="#abb2bf", insertbackground="white")
        self.rsa_log.pack(fill="both", expand=True, padx=15, pady=10)
    
    def run_rsa_standard(self):
        self.rsa_log.delete("1.0", tk.END)
        try:
            e = int(self.rsa_e.get())
            msg = self.rsa_msg.get().encode()

            pub, priv = self.rsa_system.generate_keys(e_custom=e)
            self.rsa_log.insert(tk.END, f"Bước 1: Sinh khóa\n")
            self.rsa_log.insert(tk.END, f"Khóa công khai (e, N): ({pub[0]},\n{pub[1]})\n\n")

            c = self.rsa_system.encrypt(msg, pub)
            self.rsa_log.insert(tk.END, f"Bước 2: Mã hóa\n")
            self.rsa_log.insert(tk.END, f"Bản mã C: {c}\n\n")

            self.rsa_log.insert(tk.END, f"Bước 3: Tấn công khai căn\n")
            
            m_root = iroot_e(c, e)
            self.rsa_log.insert(tk.END, f"Giá trị số nguyên m tính được từ khai căn: {m_root}\n")

            m_goc_int = int.from_bytes(msg, 'big')
            self.rsa_log.insert(tk.END, f"Giá trị số nguyên m gốc ban đầu: {m_goc_int}\n")
            
            if m_root == m_goc_int:
                self.rsa_log.insert(tk.END, f"Kết quả khai căn trùng khớp với bản rõ ban đầu!\n")
                self.rsa_log.insert(tk.END, f"Thông điệp: {m_root.to_bytes((m_root.bit_length()+7)//8, 'big').decode()}\n")
        except Exception as ex:
            messagebox.showerror("Lỗi", str(ex))

    def _setup_tab_hastad(self):
        frame_top = tk.LabelFrame(self.tab_hastad, text=" Các thông số cần thiết ", padx=15, pady=15, bg="#21252b", fg="#61afef", font=("Helvetica", 14, "bold"))
        frame_top.pack(fill="x", padx=15, pady=10)
        
        tk.Label(frame_top, text="Số mũ công khai e:", bg="#21252b", fg="#abb2bf", font=("Helvetica", 13, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.hastad_e = tk.Entry(frame_top, width=10, font=("Consolas", 14), bg="#282c34", fg="#e5c07b", insertbackground="white", bd=2)
        self.hastad_e.insert(0, "3")
        self.hastad_e.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        tk.Label(frame_top, text="Bản rõ m:", bg="#21252b", fg="#abb2bf", font=("Helvetica", 13, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.hastad_msg = tk.Entry(frame_top, width=65, font=("Consolas", 14), bg="#282c34", fg="#abb2bf", insertbackground="white", bd=2)
        self.hastad_msg.insert(0, "")
        self.hastad_msg.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        
        btn = tk.Button(self.tab_hastad, text="Thực hiện mô phỏng từng bước", command=self.run_hastad_broadcast, font=("Helvetica", 13, "bold"), bg="#61afef", fg="#1e222b", activebackground="#7ec2f5", bd=0, padx=15, pady=6)
        btn.pack(padx=15, pady=10, anchor="w")
        
        self.hastad_log = scrolledtext.ScrolledText(self.tab_hastad, wrap=tk.WORD, font=("Consolas", 13), bg="#282c34", fg="#abb2bf", insertbackground="white")
        self.hastad_log.pack(fill="both", expand=True, padx=15, pady=10)

    def run_hastad_broadcast(self):
        self.hastad_log.delete("1.0", tk.END)
        try:
            e = int(self.hastad_e.get())
            msg = self.hastad_msg.get().encode()
            
            self.hastad_log.insert(tk.END, f"Bước 1: Thu thập dữ liệu từ {e} người nhận\n")
            ciphertexts = []
            moduli = []
            
            for i in range(e):
                pub, _ = self.rsa_system.generate_keys(e_custom=e)
                c = self.rsa_system.encrypt(msg, pub)
                ciphertexts.append(int(c))
                moduli.append(int(pub[1]))
                self.hastad_log.insert(tk.END, f"Người nhận {i+1}:\n  C = {c}\n  N = {pub[1]}\n")
                
            self.hastad_log.insert(tk.END, f"\nBước 2: Sử dụng định lý CRT để tìm m^{e}...\n")
            m_pow_e = chinese_remainder_theorem(ciphertexts, moduli)
            self.hastad_log.insert(tk.END, f"Giá trị đồng dư m^{e} mod (N1*N2*...): {m_pow_e}\n\n")
            
            self.hastad_log.insert(tk.END, f"Bước 3: Tiến hành khai căn bậc {e} nguyên nguyên bản...\n")
            m_final = iroot_e(m_pow_e, e)
            self.hastad_log.insert(tk.END, f"Số nguyên phục hồi m: {m_final}\n")
            
            plain = m_final.to_bytes((m_final.bit_length() + 7) // 8, 'big')
            self.hastad_log.insert(tk.END, f"\nBản rõ suy ra từ các bước trên: {plain.decode()}\n")
        except Exception as ex:
            messagebox.showerror("Lỗi", str(ex))

    def _setup_tab_visual(self):
        self.style.configure("Sub.TNotebook", background="#21252b", borderwidth=0)
        self.style.configure("Sub.TNotebook.Tab", font=("Helvetica", 11, "bold"), padding=[12, 6], background="#282c34", foreground="#a6acb9")
        self.style.map("Sub.TNotebook.Tab", background=[("selected", "#3e4452")], foreground=[("selected", "#ffffff")])

        self.sub_notebook = ttk.Notebook(self.tab_visual, style="Sub.TNotebook")
        self.sub_notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.sub_tab_m = tk.Frame(self.sub_notebook, bg="#21252b")
        self.sub_tab_e = tk.Frame(self.sub_notebook, bg="#21252b")

        self.sub_notebook.add(self.sub_tab_m, text=" 3.1 So sánh độ dài m (Khai căn) ")
        self.sub_notebook.add(self.sub_tab_e, text=" 3.2 Đối chiếu số mũ e (Điều kiện CRT) ")

        frame_m_input = tk.LabelFrame(self.sub_tab_m, text=" Nhập dữ liệu đối chiếu điều kiện khai căn ", padx=15, pady=15, bg="#21252b", fg="#e5c07b", font=("Helvetica", 13, "bold"))
        frame_m_input.pack(fill="x", padx=15, pady=10)

        tk.Label(frame_m_input, text="Thông điệp nhỏ (m nhỏ):", bg="#21252b", fg="#abb2bf", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=5, pady=2)
        self.visual_msg_nho = tk.Entry(frame_m_input, width=80, font=("Consolas", 13), bg="#282c34", fg="#abb2bf", insertbackground="white", bd=2)
        self.visual_msg_nho.pack(fill="x", padx=5, pady=5)

        tk.Label(frame_m_input, text="Thông điệp lớn (dưới 40 ký tự):", bg="#21252b", fg="#abb2bf", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=5, pady=2)
        self.visual_msg_lon = tk.Entry(frame_m_input, width=80, font=("Consolas", 13), bg="#282c34", fg="#abb2bf", insertbackground="white", bd=2)
        self.visual_msg_lon.pack(fill="x", padx=5, pady=5)

        btn_m = tk.Button(self.sub_tab_m, text="So sánh phép khai căn", command=self.run_compare_m, font=("Helvetica", 12, "bold"), bg="#e5c07b", fg="#1e222b", activebackground="#f3d498", bd=0, padx=15, pady=6)
        btn_m.pack(padx=15, pady=5, anchor="w")

        self.m_log = scrolledtext.ScrolledText(self.sub_tab_m, wrap=tk.WORD, font=("Consolas", 13), bg="#282c34", fg="#abb2bf", insertbackground="white")
        self.m_log.pack(fill="both", expand=True, padx=15, pady=10)

        frame_e_desc = tk.LabelFrame(self.sub_tab_e, text=" Khảo sát số lượng bản mã cần chặn trên đường truyền ", padx=15, pady=15, bg="#21252b", fg="#e06c75", font=("Helvetica", 13, "bold"))
        frame_e_desc.pack(fill="x", padx=15, pady=10)

        tk.Label(frame_e_desc, text="Nhập thông điệp giả định để chạy đối chiếu hệ phương trình:", bg="#21252b", fg="#abb2bf", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=5, pady=2)
        self.visual_msg_crt = tk.Entry(frame_e_desc, width=80, font=("Consolas", 13), bg="#282c34", fg="#abb2bf", insertbackground="white", bd=2)
        self.visual_msg_crt.pack(fill="x", padx=5, pady=5)

        btn_e = tk.Button(frame_e_desc, text="Xem đối chiếu điều kiện CRT", command=self.run_compare_e, font=("Helvetica", 12, "bold"), bg="#e06c75", fg="#1e222b", activebackground="#f08f97", bd=0, padx=15, pady=6)
        btn_e.pack(padx=5, pady=10, anchor="w")

        self.e_log = scrolledtext.ScrolledText(self.sub_tab_e, wrap=tk.WORD, font=("Consolas", 13), bg="#282c34", fg="#abb2bf", insertbackground="white")
        self.e_log.pack(fill="both", expand=True, padx=15, pady=10)

    def run_compare_m(self):
        self.m_log.delete("1.0", tk.END)

        chuoi_nho = self.visual_msg_nho.get()
        chuoi_lon = self.visual_msg_lon.get()

        if not chuoi_nho or not chuoi_lon:
            messagebox.showwarning("Thông báo", "Vui lòng điền đầy đủ thông điệp nhỏ và lớn để thực hiện so sánh.")
            return

        m_nho_bytes = chuoi_nho.encode('utf-8')
        m_nho_int = int.from_bytes(m_nho_bytes, 'big')

        m_lon_bytes = chuoi_lon.encode('utf-8')
        m_lon_int = int.from_bytes(m_lon_bytes, 'big')

        if m_nho_int.bit_length() * 3 >= 1024 or m_lon_int.bit_length() * 3 >= 1024:
            messagebox.showerror("Lỗi độ dài", "Thông điệp quá dài!")
            return

        self.m_log.insert(tk.END, "Kết quả so sánh phép khai căn giữa m nhỏ và m lớn\n\n")
        try:
            n_list_nho = []
            for _ in range(3):
                pub, _ = self.rsa_system.generate_keys(e_custom=3)
                n_list_nho.append(pub[1])

            tich_n_nho = reduce(lambda x, y: x * y, n_list_nho)
            self.m_log.insert(tk.END, f"Thử nghiệm 1: Với thông điệp nhỏ ('{chuoi_nho}'):\n")
            self.m_log.insert(tk.END, f"    - Giá trị m^3  : {m_nho_int**3}\n")
            self.m_log.insert(tk.END, f"    - Tích Moduli N: {tich_n_nho}\n")
            if m_nho_int**3 < tich_n_nho:
                self.m_log.insert(tk.END, f"Kết luận: ĐỦ ĐIỀU KIỆN PHÁ MÃ (Do m^3 < Tích_N)\n\n")
            else:
                self.m_log.insert(tk.END, f"Kết luận: THẤT BẠI (Do m^3 > Tích_N)\n\n")

            n_list_lon = []
            for _ in range(3):
                pub, _ = self.rsa_system.generate_keys(e_custom=3)
                n_list_lon.append(pub[1])
                
            tich_n_lon = reduce(lambda x, y: x * y, n_list_lon)
            self.m_log.insert(tk.END, f"Thử nghiệm 2: Với thông điệp lớn ('{chuoi_lon}'):\n")
            self.m_log.insert(tk.END, f"    - Giá trị m^3  : {m_lon_int**3}\n")
            self.m_log.insert(tk.END, f"    - Tích Moduli N: {tich_n_lon}\n")
            if m_lon_int**3 < tich_n_lon:
                self.m_log.insert(tk.END, f"Kết luận: ĐỦ ĐIỀU KIỆN PHÁ MÃ (Do m^3 < Tích_N)\n")
            else:
                self.m_log.insert(tk.END, f"Kết luận: THẤT BẠI (Do m^3 > Tích_N)\n")
        except Exception as ex:
            self.m_log.insert(tk.END, f"LỖI {ex}\n")

    def run_compare_e(self):
        self.e_log.delete("1.0", tk.END)

        chuoi_mau = self.visual_msg_crt.get()
        if not chuoi_mau:
            messagebox.showwarning("Thông báo", "Vui lòng nhập thông điệp giả định trước khi chạy kiểm thử CRT.")
            return
            
        m_bytes = chuoi_mau.encode('utf-8')
        self.e_log.insert(tk.END, "Kết quả so sánh sử dụng CRT khi e nhỏ và e lớn\n\n")
        self.e_log.insert(tk.END, "Trường hợp số mũ nhỏ e = 3:\n")
        try:
            _, c_list, n_list = generate_rsa_components(m_bytes, 3)
            for i in range(3):
                self.e_log.insert(tk.END, f"Bản mã C_{i+1}: {c_list[i]}\n")
                self.e_log.insert(tk.END, f"Modulus N_{i+1}: {n_list[i]}\n")
            m_khoi_phuc_int = hastad_broadcast_attack(c_list, n_list, 3)
            m_khoi_phuc_bytes = m_khoi_phuc_int.to_bytes((m_khoi_phuc_int.bit_length() + 7) // 8, 'big')
            chuoi_khoi_phuc = m_khoi_phuc_bytes.decode('utf-8', errors='ignore')
            self.e_log.insert(tk.END, f"Bản rõ khôi phục: '{chuoi_khoi_phuc}'\n\n")
        except Exception as ex:
            self.e_log.insert(tk.END, f"LỖI {ex}\n")
            
        self.e_log.insert(tk.END, "Trường hợp số mũ lớn e = 65537:\n")
        uoc_tinh_bit = self.rsa_system.key_size * 65537
        self.e_log.insert(tk.END, f"Số lượng phương trình bắt buộc: {65537:,} phương trình\n")
        self.e_log.insert(tk.END, f"Số bit tích số Modulus chung: ~{uoc_tinh_bit:,} bits\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = HastadApp(root)
    root.mainloop()