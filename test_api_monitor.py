import urllib.request
import urllib.error

url = "http://127.0.0.1:5000/api/monitor"

for i in range(100):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            if response.status != 200:
                print(f"Request {i + 1} failed: {response.status}")
                break
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Request {i + 1} failed: {error}")
        break

else:
    print("All 100 API requests completed successfully.")