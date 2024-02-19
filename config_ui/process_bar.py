from tqdm import tqdm

def process_bar(processing_function):
    def wrapper(arg1, arg2):
        # Create bar
        progress_bar = tqdm(total=100, desc="Processing", unit="%")
       
        for _ in range(100):
            processing_function(arg1, arg2)
            progress_bar.update(1)
        progress_bar.close()

    return wrapper

