from tqdm import tqdm

def process_bar(processing_function):
    def wrapper(arg1, arg2):
        # Tạo thanh tiến trình
        progress_bar = tqdm(total=100, desc="Processing", unit="%")

        # Mô phỏng công việc
        for _ in range(100):
            # Thực hiện công việc ở đây
            processing_function(arg1, arg2)

            # Cập nhật thanh tiến trình
            progress_bar.update(1)

        # Đóng thanh tiến trình khi công việc hoàn thành
        progress_bar.close()

    return wrapper

