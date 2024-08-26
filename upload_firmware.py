import requests

def upload_file(url, file_path):
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(url, files=files)
            if response.status_code == 200:
                print("File uploaded successfully!")
            else:
                print(f"Error uploading file. Status code: {response.status_code}")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Replace with your target URL and the local file path you want to upload
    target_url = "http://speedtest.tplinkcloud.com:8080/upload/HB710v1_0.1.0_3.0.0_UP_BOOT_2024-05-08_09.11.17.bin"
    local_file_path = r"C:\Users\cciep\OneDrive\Documents\Shared\Firmware\HB710v1_0.1.0_3.0.0_UP_BOOT_2024-05-08_09.11.17.bin"

    upload_file(target_url, local_file_path)