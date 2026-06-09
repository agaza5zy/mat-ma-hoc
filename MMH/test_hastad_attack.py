import gmpy2
from functools import reduce
from typing import List, Tuple
from sympy import lcm
import pytest
import os

class RSAModule:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        # Khởi tạo trạng thái ngẫu nhiên bảo mật cho gmpy2
        self.rand_state = gmpy2.random_state(int.from_bytes(os.urandom(8), 'big'))
        
    def _get_prime(self, bits):
        """Sinh một số nguyên tố ngẫu nhiên có độ dài đúng bằng số bits."""
        res = gmpy2.mpz_urandomb(self.rand_state, bits)
        return gmpy2.next_prime(res)

    def generate_keys(self, e_custom=3):
        """Sinh cặp khóa công khai (e, n) và khóa bí mật (d, n)."""
        e = gmpy2.mpz(e_custom)
        
        while True:
            p = self._get_prime(self.key_size // 2)
            q = self._get_prime(self.key_size // 2)
            if p == q:
                continue
            lambda_n = gmpy2.mpz(lcm(int(p - 1), int(q - 1)))
            
            # Nếu gcd == 1 thì hợp lệ, thoát vòng lặp để chạy tiếp
            if gmpy2.gcd(e, lambda_n) == 1:
                break

        n = p * q
        # 4. Tính số mũ bí mật d = e⁻¹ mod λ(n)
        d = gmpy2.invert(e, lambda_n)

        return (e, n), (d, n)

    # --- MÃ HÓA & GIẢI MÃ (KHÔNG PADDING) ---
    def encrypt(self, message: bytes, pub_key):
        """Mã hóa chuỗi byte thành số nguyên bản mã c."""
        e, n = pub_key
        
        # 1. Chuyển chuỗi kí tự bytes sang số nguyên lớn kiểu mpz
        m = gmpy2.mpz(int.from_bytes(message, 'big'))
        
        # Kiểm tra điều kiện toán học bắt buộc: Tin nhắn số phải nhỏ hơn n
        if m >= n:
            raise ValueError("Tin nhắn quá dài, đổi ra số lớn hơn hoặc bằng n. Không thể mã hóa!")
            
        # 2. Tính toán công thức toán học RSA: c = m^e mod n
        c = gmpy2.powmod(m, e, n)
        return c

    def decrypt(self, ciphertext, priv_key):
        """Giải mã số nguyên bản mã c về lại chuỗi byte tin nhắn gốc."""
        d, n = priv_key
        
        # 1. Tính toán công thức toán học RSA: m = c^d mod n
        m = gmpy2.powmod(ciphertext, d, n)
        
        # 2. Tính toán độ dài số byte tối đa của khối dữ liệu n
        k = (self.key_size + 7) // 8
        
        # 3. Chuyển số nguyên m ngược lại thành chuỗi bytes
        message = int(m).to_bytes(k, 'big')
        
        # 4. Loại bỏ các byte rỗng b'\x00' thừa ở đầu chuỗi (do ép độ dài k byte)
        return message.lstrip(b'\x00')

def iroot_e(x: int, e: int) -> int:
    """
    Khai căn bậc e nguyên của x sử dụng thư viện gmpy2.
    Trả về phần nguyên của căn bậc e (is_exact không bắt buộc phải True).
    """
    if x < 0 and e % 2 == 0:
        raise ValueError("Không thể khai căn bậc chẵn của một số âm.")
    
    # gmpy2.iroot(x, e) trả về một tuple: (root, is_exact)
    root, _ = gmpy2.iroot(gmpy2.mpz(x), int(e))
    return int(root)

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Hàm tìm ước chung lớn nhất mở rộng (Extended Euclidean Algorithm)"""
    g, x, y = gmpy2.gcdext(gmpy2.mpz(a), gmpy2.mpz(b))
    return int(g), int(x), int(y)

def chinese_remainder_theorem(c_list: List[int], n_list: List[int]) -> int:
    """
    Giải hệ phương trình đồng dư bằng Định lý số dư Trung Hoa (CRT).
    X ≡ c_i (mod n_i)
    """
    total_N = reduce(lambda x, y: x * y, n_list)
    result = 0
    
    for c, n in zip(c_list, n_list):
        N_i = total_N // n
        # Tìm nghịch đảo mô-đun: (N_i * inv) % n == 1
        _, inv, _ = extended_gcd(N_i, n)
        result += c * (inv % n) * N_i
        
    return int(result % total_N)

def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int], e: int) -> int:
    """
    Triển khai tấn công Håstad's Broadcast Attack.
    Yêu cầu: Số lượng bản mã (len(ciphertexts)) phải >= e.
    """
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError(
            f"Số lượng bản mã và moduli thu được ({len(ciphertexts)}) "
            f"phải lớn hơn hoặc bằng số mũ e ({e})."
        )
    
    # Chỉ lấy đúng e cặp bản mã và moduli đầu tiên để tấn công
    c_selected = ciphertexts[:e]
    n_selected = moduli[:e]
    
    # Bước 1: Dùng CRT để tìm m^e mod (N_1 * N_2 * ... * N_e)
    m_pow_e = chinese_remainder_theorem(c_selected, n_selected)
    
    # Bước 2: Khai căn bậc e nguyên vì m^e < N_1 * N_2 * ... * N_e
    m = iroot_e(m_pow_e, e)
    
    return m

# --- helper function sinh số nguyên tố an toàn cho RSA ---
def generate_rsa_components(m_bytes: bytes, e: int, key_size: int = 512):
    """Sinh các cặp khóa RSA và bản mã tương ứng từ một thông điệp m"""
    m = int.from_bytes(m_bytes, byteorder='big')
    ciphertexts = []
    moduli = []
    
    # Tạo e cặp khóa ngẫu nhiên
    # Khởi tạo trạng thái random của gmpy2
    rand_state = gmpy2.random_state()
    
    for _ in range(e):
        while True:
            # Sửa lại gen prime dựa trên key_size được truyền vào để đồng bộ UI
            p = gmpy2.next_prime(gmpy2.mpz_urandomb(rand_state, key_size // 2))
            q = gmpy2.next_prime(gmpy2.mpz_urandomb(rand_state, key_size // 2))
            n = int(p * q)
            
            lambda_n = gmpy2.mpz(lcm(int(p - 1), int(q - 1)))
            
            if gmpy2.gcd(e, lambda_n) == 1 and n > m**e and n not in moduli: 
                moduli.append(n)
                break
        
        c = int(pow(m, e, n))
        ciphertexts.append(c)
        
    return m, ciphertexts, moduli


# ==========================================
# BỔ SUNG CÁC HÀM FIX THEO YÊU CẦU CỦA TASK
# ==========================================

# FIX-3: Thêm hàm phân tích tấn công khai căn chi tiết từng bước cho UI
def attack_direct_iroot_verbose(c: int, e: int, n: int) -> dict:
    root, exact = gmpy2.iroot(gmpy2.mpz(c), int(e))
    root_int = int(root)
    exact_bool = bool(exact)
    root_repow_mod_n = int(pow(root_int, e, n))
    success = (root_repow_mod_n == c)
    
    # Kiểm tra xem c có thực sự bằng m^e trên tập số nguyên không
    condition_met = exact_bool and (root_int ** e == c)

    return {
        "m_pow_e_raw": int(c),
        "condition_met": condition_met,
        "root": root_int,
        "exact": exact_bool,
        "root_repow_mod_n": root_repow_mod_n,
        "success": success
    }


# ==========================================
# CÁC BÀI KIỂM THỬ (TEST CASES)
# ==========================================

def test_iroot_exact_cube():
    """Kiểm tra khai căn bậc 3 chính xác"""
    assert iroot_e(27, 3) == 3
    assert iroot_e(1000, 3) == 10

def test_iroot_inexact():
    """Kiểm tra khai căn số không chính xác (lấy phần nguyên)"""
    assert iroot_e(28, 3) == 3
    assert iroot_e(26, 3) == 2

def test_large_number():
    """Kiểm tra với số cực lớn (Edge case: m lớn)"""
    large_base = 123456789012345678901234567890
    e = 65537
    power = large_base ** e
    assert iroot_e(power, e) == large_base

def test_crt_standard():
    """Kiểm tra CRT với hệ phương trình cơ bản"""
    # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7) -> x = 23
    assert chinese_remainder_theorem([2, 3, 2], [3, 5, 7]) == 23

def test_hastad_small_m():
    """Test Håstad với thông điệp nhỏ (e=3)"""
    e = 3
    secret_msg = b"Hi"
    m_expected, ciphertexts, moduli = generate_rsa_components(secret_msg, e, key_size=128)
    
    m_attacked = hastad_broadcast_attack(ciphertexts, moduli, e)
    assert m_attacked == m_expected
    assert m_attacked.to_bytes((m_attacked.bit_length() + 7) // 8, 'big') == secret_msg

def test_hastad_large_m():
    """Test Håstad với thông điệp lớn sát flag thật (Edge Case: m lớn, e=5)"""
    e = 5
    secret_msg = b"FLAG{H4st4d_Bro4dc4st_4tt4ck_W1th_Gmpy2_Is_S0_F4st_2026}"
    m_expected, ciphertexts, moduli = generate_rsa_components(secret_msg, e, key_size=1024)
    
    # FIX-1: Bổ sung block assertion bị thiếu cho test_hastad_large_m
    m_attacked = hastad_broadcast_attack(ciphertexts, moduli, e)
    assert m_attacked == m_expected
    assert m_attacked.to_bytes((m_attacked.bit_length() + 7) // 8, 'big') == secret_msg

# FIX-2: Thêm test case kiểm thử kịch bản tấn công khai căn THẤT BẠI do m quá lớn (m^e > n)
def test_direct_iroot_fails_large_m():
    e = 3
    n_bits = 128
    rsa = RSAModule(key_size=n_bits)
    pub, priv = rsa.generate_keys(e_custom=e)
    n = pub[1]
    
    # Chọn m sao cho m < n (để hợp lệ rsa) nhưng m^3 > n
    m = n // 2
    assert m < n
    assert m**3 > n
    
    c = int(pow(m, e, n))
    root = iroot_e(c, e)
    
    # Tấn công khai căn trực tiếp phải thất bại (kết quả sai lệch)
    assert root != m
    
    # Xác minh cờ exact từ gmpy2.iroot phải trả về False
    _, is_exact = gmpy2.iroot(gmpy2.mpz(c), e)
    assert bool(is_exact) is False

def test_root_attack_fail_m_pow_e_greater_than_n():
    """Kiểm tra kịch bản tấn công khai căn THẤT BẠI khi m^e > N (bản cũ giữ lại)"""
    e = 3
    rsa = RSAModule(key_size=64)
    pub, priv = rsa.generate_keys(e_custom=e)
    N = pub[1]
    m = N - 10 
    assert m**e > N
    c = gmpy2.powmod(m, e, N)
    m_fake = iroot_e(int(c), e)
    assert m_fake != m