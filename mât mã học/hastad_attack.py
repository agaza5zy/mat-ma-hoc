import pytest
import gmpy2
from hastad_attack import iroot_e, chinese_remainder_theorem, hastad_broadcast_attack

# --- helper function sinh số nguyên tố an toàn cho RSA ---
def generate_rsa_components(m_bytes: bytes, e: int):
    """Sinh các cặp khóa RSA và bản mã tương ứng từ một thông điệp m"""
    m = int.from_bytes(m_bytes, byteorder='big')
    ciphertexts = []
    moduli = []
    
    # Tạo e cặp khóa ngẫu nhiên
    # Khởi tạo trạng thái random của gmpy2
    rand_state = gmpy2.random_state()
    
    for _ in range(e):
        while True:
            p = gmpy2.next_prime(gmpy2.mpz_urandomb(rand_state, 512))
            q = gmpy2.next_prime(gmpy2.mpz_urandomb(rand_state, 512))
            n = int(p * q)
            if n > m**e and n not in moduli: # Đảm bảo điều kiện tấn công và n là duy nhất
                moduli.append(n)
                break
        
        c = int(pow(m, e, n))
        ciphertexts.append(c)
        
    return m, ciphertexts, moduli


## =====================================================================
## UNIT TESTS FOR IROOT
## =====================================================================

def test_iroot_exact_cube():
    """Kiểm tra khai căn bậc 3 chính xác"""
    assert iroot_e(27, 3) == 3
    assert iroot_e(1000, 3) == 10

def test_iroot_inexact():
    """Kiểm tra khai căn số không chính xác (lấy phần nguyên)"""
    assert iroot_e(28, 3) == 3
    assert iroot_e(26, 3) == 2

def test_iroot_large_number():
    """Kiểm tra với số cực lớn (Edge case: m lớn)"""
    large_base = 123456789012345678901234567890
    e = 65537
    power = large_base ** e
    assert iroot_e(power, e) == large_base


## =====================================================================
## UNIT TESTS FOR CRT
## =====================================================================

def test_crt_standard():
    """Kiểm tra CRT với hệ phương trình cơ bản"""
    # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7) -> x = 23
    assert chinese_remainder_theorem([2, 3, 2], [3, 5, 7]) == 23


## =====================================================================
## UNIT TESTS FOR HÅSTAD ATTACK & EDGE CASES
## =====================================================================

def test_hastad_small_m():
    """Test Håstad với thông điệp nhỏ (e=3)"""
    e = 3
    secret_msg = b"Hi"
    m_expected, ciphertexts, moduli = generate_rsa_components(secret_msg, e)
    
    m_attacked = hastad_broadcast_attack(ciphertexts, moduli, e)
    assert m_attacked == m_expected
    assert m_attacked.to_bytes((m_attacked.bit_length() + 7) // 8, 'big') == secret_msg

def test_hastad_large_m():
    """Test Håstad với thông điệp lớn sát flag thật (Edge Case: m lớn, e=5)"""
    e = 5
    secret_msg = b"FLAG{H4st4d_Bro4dc4st_4tt4ck_W1th_Gmpy2_Is_S0_F4st_2026}"
    m_expected, ciphertexts, moduli = generate_rsa_components(secret_msg, e)
    
    m_attacked = hastad_broadcast_attack(ciphertexts, moduli, e)
    assert m_attacked == m_expected

def test_hastad_insufficient_ciphertexts():
    """Edge case: Lỗi khi không thu thập đủ số lượng bản mã bằng e"""
    e = 3
    ciphertexts = [12, 34] # Chỉ có 2 bản mã trong khi e = 3
    moduli = [55, 77]
    
    with pytest.raises(ValueError, match="phải lớn hơn hoặc bằng số mũ e"):
        hastad_broadcast_attack(ciphertexts, moduli, e)