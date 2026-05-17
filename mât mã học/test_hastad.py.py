import gmpy2
from functools import reduce
from typing import List, Tuple

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