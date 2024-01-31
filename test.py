import pytz
from datetime import datetime

def get_gmt_offset(timezone_name):
    # Lấy thời điểm hiện tại
    now = datetime.now()

    # Tạo đối tượng múi giờ từ tên múi giờ
    timezone = pytz.timezone(timezone_name)

    # Lấy chênh lệch giờ so với UTC/GMT
    gmt_offset = timezone.utcoffset(now).total_seconds() // 3600  # Chuyển đổi thành giờ
    
    return gmt_offset

# Ví dụ với múi giờ "Asia/Bangkok"
timezone_name = "Asia/Bangkok"
gmt_offset = get_gmt_offset(timezone_name)

print(f"Múi giờ {timezone_name} có chênh lệch giờ so với GMT là {gmt_offset} giờ.")
