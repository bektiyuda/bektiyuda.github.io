---
title: "Schematics NPC CTF 2025 Quals"
description: "Write ups from the challenge that I solved alongside with collaboration of my team HARO2b in Qualifications of SCHEMATICS NPC CTF 2025 CTF"
pubDate: "Oct 19 2025"
heroImage: "/images/sch/HeaderNPC.jpg"
---

Write ups from the challenge that I solved alongside with collaboration of my team `HARO2b` in Qualifications of SCHEMATICS NPC CTF 2025 CTF. This is my team score when it got freezed :

![](/images/sch/ScoreBoard.png)

## Web
### wongpress

#### Description
you need to know how wordpress's ecosystem works, you are SUBS!

*note:
- this is CTF challenge wordpress plugin based
- /register is only for creating new user accounts, there are NO VULNERABILITIES RELATED TO THE FLAG there!

#### Solution

![](/images/sch/wongpress/image.png)

Given the WordPress website that has a register feature. After registration, we can't access the login page because it got defaced.

From the given source code, there is `xmlrpc_authenticate`, a function in the xmlrpc.php that can be the way for us to login via XML-RPC.

![](/images/sch/wongpress/image-1.png)

With calling this method in xmlrpc.php request and entering the registered creds, we can login and get the cookie (wordpress_logged_in_*) for the further recon.

In our analysis of the source code, there is an interesting function which is `schedule_content_shortcode`. This function registers shortcode `[schedule_content]` and accepts filter attributes. Filter value is compared with the blacklist, if it `passes` it is copied to the `echo shell` then executed with `exec()`. This can be our way to get RCE.

The thing is, to check the content we create we must become the allowed_roles.

Checking the other functions, there is a function that can update the user role from subscriber to the contributor `(update_user_preferences)`. All we need is just nonce that can be got after we login (check the xmlrpc_authenticate).

![](/images/sch/wongpress/image-2.png)

We send the request to the /wp-admin/admin-ajax.php along with cookie, nonce, and action which value is `update_user_preferences`. We got success response to upgrade our role.

![](/images/sch/wongpress/image-3.png)

After that, we can finally create a post and check it. We inject `metaWeblog.newPost` with `[schedule_content filter='$(ls)']` and the web responds with the ID of the content. 

![](/images/sch/wongpress/image-4.png)
![](/images/sch/wongpress/flag.png)

So we can access this via `/?p=$ID&preview=true`, and the response shows we got RCE then read the flag with `[schedule_content filter='$(base64$IFS-w0$IFS*ag\*)']` because of the blacklist.

#### Flag
SCH25{m44f_y4_p3r74m4_k4l1_8u47_ch4113n63_w0rdpr355_p1u61n_b4c_70_c0mm4nd_1nj3c710n_hahahahahahahahaha}

## Forensic
### Computero

#### Description
Seorang hacker berhasil mengencrypt seluruh dokumen milik rey. Padahal salah satu dokumen tersebut memiliki pesan yang sangat penting. Untungnya, hacker tidak membuang permanen jejak-jejak penyerangannya. Bantulah rey mendapatkan pesan pentingnya kembali.

#### Solution

![](/images/sch/computero/Screenshot%202025-10-18%20195222.png)

Loading the artifact to Autopsy, we found a deleted file `ransom.exe` along with encrypted files.

![](/images/sch/computero/Screenshot%202025-10-18%20193419.png)

Extract the ransom.exe and all of the encrypted files. When analyzing ransom.exe with pyi-archive_viewer we found an object named `encryptor`, so we extracted this object.

![](/images/sch/computero/Screenshot%202025-10-18%20193807.png)

The output is encoded data that hides the source code. I asked GPT to return the actual source code, it turns out that the flow of the encoding is `reverse -> base64 -> zlib` that was done repeatedly.

For the decryptor, just reverse it and since the encrypted files are PNGs, we can `predict the IV` with `KPA on the PNG Header`. This is the decryptor code:

```python
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from pathlib import Path
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

KEY = b'sacred_key_32145'
INPUT_DIR = Path("gambar")
OUTPUT_DIR = Path("out_decrypted")
PNG_BLOCK0 = bytes.fromhex("89504E470D0A1A0A0000000D49484452")

def recover_iv_and_decrypt(ciphertext: bytes, key: bytes, first_plain_block: bytes) -> bytes:
    if len(ciphertext) < 16:
        raise ValueError("ciphertext too short (< 16 bytes)")
    C0 = ciphertext[:16]
    ecb = AES.new(key, AES.MODE_ECB)
    D0 = ecb.decrypt(C0)
    iv = bytes(a ^ b for a, b in zip(D0, first_plain_block))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)
    return unpad(pt, AES.block_size)

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    targets = sorted(INPUT_DIR.rglob("*.png.enc"))
    if not targets:
        print(f"[!] No *.png.enc files found under: {INPUT_DIR.resolve()}")
        return
    ok, fail = 0, 0
    for src in targets:
        rel = src.relative_to(INPUT_DIR)
        out = OUTPUT_DIR / rel.with_suffix("").with_suffix(".png")
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = src.read_bytes()
            plain = recover_iv_and_decrypt(data, KEY, PNG_BLOCK0)
            if not plain.startswith(bytes.fromhex("89504E470D0A1A0A")):
                print(f"[?] {src}: decrypted but does not start with PNG signature (writing anyway)")
            out.write_bytes(plain)
            ok += 1
            print(f"[+] OK  -> {out}")
        except Exception as e:
            fail += 1
            print(f"[-] FAIL {src} : {e}")
    print(f"\nDone. Success: {ok}  |  Failed: {fail}  |  Output dir: {OUTPUT_DIR.resolve()}")

if __name__ == "__main__":
    main()
```

After we decrypt all of the files, the flag is in the `179-Screenshot (224).png` file.

#### Flag
SCH25{fl4ggknyA_In111_y4h_B4ng_Cr0c0dilldildilololo}

### Mistakez

#### Description
Keke menjadi admin sebuah web pemesanan makanan. Tetapi tiba - tiba Keke tidak bisa login ke akun admin, setelah diperiksa ternyata password akun admin telah berubah. Hal ini terjadi karena Keke tidak memeriksa kembali aturan dari edit profil.

Tolong bantu Keke menemukan username milik user yang mengganti password dari akun admin

Format flag : SCH25{Username_milik_user_yang_mengganti_password_dari_akun_admin}

#### Solution
The changing password usually requested from HTTP POST, so we filter the packet with `http.request.method == "POST"`.

![](/images/sch/mistakez/Screenshot%202025-10-18%20175133.png)

From the filter, we found the first request to the endpoint `EditProfile.php`, so we assume that this is the valid session for admin and saved the cookie.

![](/images/sch/mistakez/Screenshot%202025-10-18%20175448.png)

In further analysis, we found another user making a request to edit profile at frame `2512`. The cookie was `o5k1b0avhka3q6aeg4dg26888b`, which is different from the admin cookie before. 

![](/images/sch/mistakez/Screenshot%202025-10-18%20180231.png)

With this sus cookie, we can get the user from `/login.php` and the user is `InfokanCaraMembantaiETS`.

#### Flag
SCH25{InfokanCaraMembantaiETS}

## Reverse
### Flagle

#### Description
just play it bro

#### Solution

From the decompiled code, the main function is found at `FUN_0040390b`, a dispatcher that obfuscates a function pointer table using XOR key `0xDEADBEEFCAFEBABE`. The state value is stored in the context buffer, and while the state is not 7, the program fetches a handler from the XOR'd table, restores the original address by XOR'ing again, then calls it. This immediately indicates a state machine that terminates at state 7.

The first handler, `FUN_00403128` (state 0), performs initialization, reads a path, opens a file and reads one 32-bit number that must be ≤ 2, then calls `FUN_004020b5` three times on three pointers within the context.

`FUN_004020b5` is simply an in-place C-string decoder that iterates until a null byte and XORs each byte with a 1-byte key. The key argument used in state 0 is `0xAB`.

Inside `FUN_00402880`, we can see how validation works. First, the program builds a 59-byte target sequence from two resources. After that, it checks each position i from 0 to 58. The guess character is transformed through `FUN_00402061(ch, i, resource4)` then compared with `target[i]`. If equal, the triplet status remains 0; if not, status is set to 2.

Function `FUN_00402061` is simply a lookup into a 256-byte table just built for index i through `FUN_00401ef1`. That's where the cryptographic pattern is revealed. `FUN_00401ef1` generates a substitution table by creating a key string `"%s_pos_%d_v2"` combining "resource4" and index, hashing with a 32-byte hash (likely SHA-256), running Fisher–Yates shuffle on array 0..255 with swap index.

In `FUN_0040390b` earlier, there's initialization of three local pointers to three global data symbols. This becomes a strong assumption because at `&DAT_00a501d0`, when XOR'ing back the first byte `0xF8 ^ 0xAB`, the result is `0x53` which is character 'S', followed by `0xC8 ^ 0xAB = 'c'`, `0xC3 ^ 0xAB = 'h'`, `0xCE ^ 0xAB = 'e'`, immediately revealing the prefix "Sche…"; XOR'ing the entire sequence until 00 produces `SchematicsCTF2025`.

![](/images/sch/flagle/Screenshot%202025-10-18%20235704.png)

With this, we can obtain three plaintext resources: `SchematicsCTF2025` as the table basis, custom alphabet for decoder (resource 3), and hexadecimal payload that after parsing produces the target (resource 1). The rest is to build per-index substitution tables from `"{SchematicsCTF2025}_pos_{i}_v2"` using SHA-256 as Fisher–Yates seed, then for each position find input byte x such that `table_i[x] == target[i]`.

#### Flag
SCH25{since_when_did_wordle_became_this_annoying__6675636b}
