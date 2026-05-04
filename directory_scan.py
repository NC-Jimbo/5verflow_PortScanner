import requests
from concurrent.futures import ThreadPoolExecutor

class DirectoryScanner:
    def __init__(self, base_url, wordlist_path):
        self.base_url = base_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.timeout = 3  # 서버 응답 대기 시간

    def _load_wordlist(self):
        """common.txt 파일에서 단어들을 읽어옵니다."""
        try:
            with open(self.wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] 에러: {self.wordlist_path} 파일을 찾을 수 없습니다.")
            return []

    def _check_url(self, word):
        """실제로 서버에 요청을 보내고 응답 코드를 분석합니다."""
        url = f"{self.base_url}/{word}"
        try:
            # allow_redirects=False로 설정하여 리다이렉트(301, 302)를 직접 확인합니다.
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            self.analyze_responses(url, response.status_code)
        except requests.RequestException:
            # 연결 실패 등은 무시합니다.
            pass

    def analyze_responses(self, url, status_code):
        """응답 코드에 따라 결과를 화면에 출력합니다."""
        if status_code == 200:
            print(f"[+] [200 OK] Found: {url}")
        elif status_code == 403:
            print(f"[!] [403 Forbidden] Exists but Access Denied: {url}")
        elif status_code in [301, 302]:
            print(f"[*] [{status_code} Redirect] Path exists: {url}")

    def brute_force_paths(self):
        """멀티스레딩을 사용하여 스캔을 시작합니다."""
        words = self._load_wordlist()
        if not words:
            return

        print(f"[*] 스캔 시작: {self.base_url} (단어 수: {len(words)})")
        print("-" * 50)

        #  100개의 스레드(동시 요청)를 사용
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(self._check_url, words)

        print("-" * 50)
        print("[*] 스캔 완료.")

if __name__ == "__main__":
    # 블루팀 서버 IP
    TARGET_URL = "http://13.54.249.195:8888" 
    WORDLIST = "wordlists/common.txt"

    scanner = DirectoryScanner(TARGET_URL, WORDLIST)
    scanner.brute_force_paths()