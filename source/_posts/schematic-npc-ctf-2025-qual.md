---
title: "Schematics NPC CTF 2025 Quals"
date: 2025-10-19 17:01:20
tags:
  - WordPress
  - Cryptography
  - Network-Analysis
  - Binary-Analysis
  - RCE
categories:
  - Web Exploitation
  - Forensic
  - Reverse Engineering
cover: /covers/HeaderNPC.jpg
author: 2byte
sticky: false
toc: true
excerpt: "Write ups from the challenge that I solved alongside with collaboration of my team `HARO2b` in Qualifications of SCHEMATICS NPC CTF 2025 CTF"
---

Write ups from the challenge that I solved alongside with collaboration of my team `HARO2b` in Qualifications of SCHEMATICS NPC CTF 2025 CTF. This is my team score when it got freezed :

![](../images/sch/ScoreBoard.png)

## wongpress - [Web]

### Description
you need to know how wordpress's ecosystem works, you are SUBS!

*note:

- this is CTF challenge wordpress plugin based
- /register is only for creating new user accounts, there are NO VULNERABILITIES RELATED TO THE FLAG there!

### Solution

![](../images/sch/wongpress/image.png)

Given the WordPress website that has a register feature. After registration, we can't access the login page because it got defaced.

```php
    public function xmlrpc_authenticate($args) {
        $username = $args[0];
        $password = $args[1];
        
        $user = wp_authenticate($username, $password);
        
        if (is_wp_error($user)) {
            return new IXR_Error(403, 'Authentication failed');
        }
        
        wp_set_auth_cookie($user->ID, true);
        
        $auth_cookie = wp_generate_auth_cookie($user->ID, time() + 172800, 'logged_in');
        
        header('Set-Cookie: ' . LOGGED_IN_COOKIE . '=' . $auth_cookie . '; path=' . COOKIEPATH . '; domain=' . COOKIE_DOMAIN . '; HttpOnly', false);
        
        $this->log_analytics($user->ID, 'xmlrpc_login', 'User logged in via XML-RPC');
        
        return array(
            'success' => true,
            'user_id' => $user->ID,
            'user_login' => $user->user_login,
            'cookie' => $auth_cookie,
            'display_name' => $user->display_name,
            'email' => $user->user_email
        );
    }
```

From the given source code, there is `xmlrpc_authenticate`, a function in the xmlrpc.php that can be the way for us to login via XML-RPC.

![](../images/sch/wongpress/image-1.png)

With calling this method in xmlrpc.php request and entering the registered creds, we can login and get the cookie (wordpress_logged_in_*) for the further recon.

```php
    public function schedule_content_shortcode($atts) {
        $atts = shortcode_atts(array(
            'type'   => 'list',
            'format' => 'html',
            'filter' => ''
        ), $atts);
        
        $blacklist = array(
            'cat', 'tac', 'more', 'less', 'head', 'tail',
            'base32', 'join', 'xxd', 'hexdump', 'od',
            'uuencode', 'uudecode', 'basenc', 'iconv',
            'curl', 'wget', 'nc', 'netcat', 'gzip', 'bzip2',
            'bash', 'sh', 'zsh', 'python', 'perl', 'ruby', 'php',
            'exec', 'system', 'passthru', 'shell_exec', 'popen',
            'flag', '/flag', 'txt', '.txt', '&', '|', ';', '`',
            'nl', 'grep', 'sed', 'awk', 'sort', 'cut', 'uniq',
            'rev', 'strings', 'dd', 'cp', 'mv', 'find', 'xargs',
            'tr', 'fold', 'fmt', 'pr', 'paste', 'base16', 'split',
            'comm', 'diff', 'patch', 'tee', 'wc', 'expand', '.', '?',
            ' ', '%', ' ', ',', '\'', 'fl', '_', '/'
        );
        
        if (!empty($atts['filter'])) {
            $filter_lower = strtolower($atts['filter']);
            foreach ($blacklist as $blocked) {
                if (strpos($filter_lower, $blocked) !== false) {
                    return '<div class="error">Invalid filter parameter detected.</div>';
                }
            }
            
            $safe_filter = str_replace(array('"', "'", '\\'), '', $atts['filter']);
            
            $output = array();
            $result_code = 0;
            $command = "echo " . $safe_filter . " 2>&1";
            exec($command, $output, $result_code);
            
            if ($atts['format'] === 'json') {
                return '<pre>' . json_encode(array(
                    'status' => 'processed',
                    'filter' => $atts['filter'],
                    'result' => implode("\n", $output)
                ), JSON_PRETTY_PRINT) . '</pre>';
            }
            
            return '<div class="content-result">' . esc_html(implode("\n", $output)) . '</div>';
        }

        $nonce_field = '';
        if (is_user_logged_in()) {
            $nonce_field = '<input type="hidden" id="pcs_nonce" value="' . esc_attr(wp_create_nonce($this->nonce_action)) . '">';
        }
        
        return '<div class="schedule-content">
            <h3>Premium Content Scheduler</h3>
            <p>Use filter parameter to customize content display.</p>'
            . $nonce_field .
        '</div>';
    }
```

In our analysis of the source code, there is an interesting function which is `schedule_content_shortcode`. This function registers shortcode `[schedule_content]` and accepts filter attributes. Filter value is compared with the blacklist, if it `passes` it is copied to the `echo shell` then executed with `exec()`. This can be our way to get RCE.

```php
    public function create_protected_page() {
        $page_check = get_page_by_path($this->protected_page_slug);
        
        if (!$page_check) {
            $page_data = array(
                'post_title'    => 'Premium Dashboard',
                'post_name'     => $this->protected_page_slug,
                'post_content'  => '<h2>Welcome to Premium Dashboard</h2>
                <p>Manage your scheduled content and premium features.</p>
                [user_stats]
                [schedule_list]
                [content_calendar]',
                'post_status'   => 'publish',
                'post_type'     => 'page',
                'post_author'   => 1
            );
            
            wp_insert_post($page_data);
        }
    }
```
```php
    public function check_page_access() {
        if (is_page($this->protected_page_slug)) {
            if (!is_user_logged_in()) {
                wp_redirect(wp_login_url());
                exit;
            }
            
            $user = wp_get_current_user();
            $allowed_roles = array('contributor', 'author', 'editor', 'administrator');
            
            if (!array_intersect($allowed_roles, $user->roles)) {
                wp_die('Access Denied: Premium Dashboard requires Contributor level or higher.', 'Access Denied', array('response' => 403));
            }
        }
    }
```

The thing is, to check the content we create we must become the allowed_roles.

```php
    public function update_user_preferences() {
        check_ajax_referer($this->nonce_action, 'nonce');

        if (!is_user_logged_in()) {
            wp_send_json_error('Not authenticated', 401);
        }
        
        $user = wp_get_current_user();
        
        if (in_array('subscriber', (array) $user->roles, true)) {
            $user->remove_role('subscriber');
            $user->add_role('contributor');
            
            $this->log_analytics($user->ID, 'role_upgraded', 'User upgraded to contributor');
            
            wp_send_json_success(array(
                'message' => 'Content preferences updated successfully',
                'level'   => 'premium'
            ));
        }
        
        wp_send_json_error('Invalid request', 400);
    }
```

Checking the other functions, there is a function that can update the user role from subscriber to the contributor `(update_user_preferences)`. All we need is just nonce that can be got after we login (check the xmlrpc_authenticate).

![](../images/sch/wongpress/image-2.png)

We send the request to the /wp-admin/admin-ajax.php along with cookie, nonce, and action which value is `update_user_preferences`. We got success response to upgrade our role.

![](../images/sch/wongpress/image-3.png)

After that, we can finally create a post and check it. We inject `metaWeblog.newPost` with `[schedule_content filter='$(ls)']` and the web responds with the ID of the content. 

![](../images/sch/wongpress/image-4.png)
![](../images/sch/wongpress/flag.png)

So we can access this via `/?p=$ID&preview=true`, and the response shows we got RCE then read the flag with `[schedule_content filter='$(base64$IFS-w0$IFS*ag\*)']` because of the blacklist.

### Flag
SCH25{m44f_y4_p3r74m4_k4l1_8u47_ch4113n63_w0rdpr355_p1u61n_b4c_70_c0mm4nd_1nj3c710n_hahahahahahahahaha}

## Computero - [Forensics]

### Description
Seorang hacker berhasil mengencrypt seluruh dokumen milik rey. Padahal salah satu dokumen tersebut memiliki pesan yang sangat penting. Untungnya, hacker tidak membuang permanen jejak-jejak penyerangannya. Bantulah rey mendapatkan pesan pentingnya kembali.

https://drive.google.com/file/d/11EIBwPIyQ0UA3s3_1xNAGHdN4zZFNTk-/view?usp=sharing 
pass: cmV5YWRhbGFocGVtYnVhdHNvYWxpbml5YW5nc2VkYW5nZGl0b250b25vbGVobGF2YWRvcmU
xMjM=

### Solution

![](../images/sch/computero/Screenshot%202025-10-18%20195222.png)

Loading the artifact to Autopsy, we found a deleted file `ransom.exe` along with encrypted files.

![](../images/sch/computero/Screenshot%202025-10-18%20193419.png)

Extract the ransom.exe and all of the encrypted files. When analyzing ransom.exe with pyi-archive_viewer (because pylingual was down at that time) we found an object named `encryptor`, so we extracted this object.

![](../images/sch/computero/Screenshot%202025-10-18%20193807.png)

The output is encoded data that hides the source code. I asked GPT to return the actual source code, it turns out that the flow of the encoding is `reverse -> base64 -> zlib` that was done repeatedly. The actual code is here:

```python
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
import os


key = b'sacred_key_32145'
file_in = 'Screenshot a.png'
file_out = 'encrypted_image.png.enc'


def encrypt_file(input_file, output_file, encryption_key):
    try:
        with open(input_file, 'rb') as f_in:
            plaintext = f_in.read()


        iv = get_random_bytes(16)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))


        with open(output_file, 'wb') as f_out:
            f_out.write(ciphertext)
       
        print(f"File '{input_file}' encrypted to '{output_file}' successfully.")


    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file}'")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    encrypt_file(file_in, file_out, key)
```

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
    return unpad(pt, AES.block_size)  # PKCS#7


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

### Flag
SCH25{fl4ggknyA_In111_y4h_B4ng_Cr0c0dilldildilololo}

## Mistakez - [Forensics]

### Description
Keke menjadi admin sebuah web pemesanan makanan. Tetapi tiba - tiba Keke tidak bisa login ke akun admin, setelah diperiksa ternyata password akun admin telah berubah. Hal ini terjadi karena Keke tidak memeriksa kembali aturan dari edit profil.

Tolong bantu Keke menemukan username milik user yang mengganti password dari akun admin

Format flag : SCH25{Username_milik_user_yang_mengganti_password_dari_akun_admin}

contoh : username = baba12345 maka isi flag seperti ini : SCH25{baba12345}

### Solution
The changing password usually requested from HTTP POST, so we filter the packet with `http.request.method == "POST"`.

![](../images/sch/mistakez/Screenshot%202025-10-18%20175133.png)

From the filter, we found the first request to the endpoint `EditProfile.php`, so we assume that this is the valid session for admin and saved the cookie.

![](../images/sch/mistakez/Screenshot%202025-10-18%20175448.png)

In further analysis, we found another user making a request to edit profile at frame `2512`. The cookie was `o5k1b0avhka3q6aeg4dg26888b`, which is different from the admin cookie before. 

![](../images/sch/mistakez/Screenshot%202025-10-18%20180231.png)

With this sus cookie, we can get the user from `/login.php` and the user is `InfokanCaraMembantaiETS`.

### Flag
SCH25{InfokanCaraMembantaiETS}

## Flagle - [Reverse]

### Description
just play it bro

### Solution

From the decompiled code, the main function is found at `FUN_0040390b`, a dispatcher that obfuscates a function pointer table using XOR key `0xDEADBEEFCAFEBABE`. The state value is stored in the context buffer, and while the state is not 7, the program fetches a handler from the XOR'd table, restores the original address by XOR'ing again, then calls it. This immediately indicates a state machine that terminates at state 7.

```c
undefined8 FUN_0040390b(void)
{
  long lVar1;
  uint *puVar2;
  uint local_388 [210];
  byte *local_40;
  undefined *local_38;
  undefined *local_30;
  code *local_20;
  ulong local_18;
  uint local_c;
  
  puVar2 = local_388;
  for (lVar1 = 0x6d; lVar1 != 0; lVar1 = lVar1 + -1) {
    puVar2[0] = 0;
    puVar2[1] = 0;
    puVar2 = puVar2 + 2;
  }
  local_40 = &BYTE_00a50120;
  local_38 = &DAT_00a501d0;
  local_30 = &DAT_00a50200;
  local_18 = 0xdeadbeefcafebabe;
  for (local_c = 0; local_c < 8; local_c = local_c + 1) {
    (&PTR_FUN_00a50260)[(int)local_c] =
         (undefined *)((ulong)(&PTR_FUN_00a50260)[(int)local_c] ^ 0xdeadbeefcafebabe);
  }
  while (local_388[0] != 7) {
    local_20 = (code *)((ulong)(&PTR_FUN_00a50260)[local_388[0]] ^ local_18);
    (*local_20)(local_388);
  }
  return 0;
}
```

The first handler, `FUN_00403128` (state 0), performs initialization, reads a path, opens a file and reads one 32-bit number that must be ≤ 2, then calls `FUN_004020b5` three times on three pointers within the context.

```c
void FUN_00403128(undefined4 *param_1)
{
  int local_11c;
  undefined1 local_118 [264];
  long local_10;
  
  FUN_00401d85();
  FUN_00403002(param_1);
  FUN_00401d85();
  FUN_00402b8a();
  FUN_0040210f(local_118,0x100);
  local_10 = FUN_007debf0(local_118,&DAT_00891065);
  local_11c = 0;
  if (local_10 != 0) {
    FUN_007dedb0(&local_11c,4,1,local_10);
    FUN_007de520(local_10);
  }
  if (2 < local_11c) {
    FUN_007df430(&DAT_00891068);
    FUN_007cd3e0(1);
  }
  param_1[1] = 0;
  FUN_00401d85();
  FUN_004020b5(*(undefined8 *)(param_1 + 0xd2),0xffffffab,0);
  FUN_00401d85();
  FUN_004020b5(*(undefined8 *)(param_1 + 0xd4),0xffffffab,0);
  FUN_00401d85();
  FUN_004020b5(*(undefined8 *)(param_1 + 0xd6),0xffffffab,0);
  FUN_00401d85();
  FUN_00402c87(&PTR_FUN_00a50260,0x40);
  *param_1 = 1;
  return;
}
```

`FUN_004020b5` is simply an in-place C-string decoder that iterates until a null byte and XORs each byte with a 1-byte key. The key argument used in state 0 is `0xAB`. In conclusion, there are three important strings stored obfuscated in .data and decoded with XOR `0xAB` at program start. These three "resources" will later become comparison material and the basis for building per-position substitution tables.

```c
undefined8 FUN_004020b5(long param_1,byte param_2)
{
  undefined4 local_c;
  
  for (local_c = 0; *(char *)(param_1 + local_c) != '\0'; local_c = local_c + 1) {
    *(byte *)(param_1 + local_c) = *(byte *)(param_1 + local_c) ^ param_2;
  }
  return 0;
}
```

State 1 (`FUN_004033d4`) ensures the attempt count is less than three, requests a guess, and stores it at `param_1+3`.

```c
void FUN_004033d4(undefined4 *param_1)
{
  FUN_00401d85();
  FUN_00402b8a();
  if ((int)param_1[1] < 3) {
    FUN_007cfae0("Attempt %d/3\nEnter your guess (A-Z, a-z, 0-9, _{}): \n",param_1[1] + 1);
    FUN_007de8f0(param_1 + 3,0x77,PTR_DAT_00a530f8);
    *param_1 = 2;
  }
  else {
    *param_1 = 5;
  }
  return;
}
```

State 2 (`FUN_00403474`) trims newline, enforces 59-byte length (`0x3B`), then builds an array of triplets containing {character, index, status=0} and calls `FUN_0040302d` before proceeding to state 3. `FUN_0040302d` itself is just a series of trampolines that ultimately falls to `FUN_00402880`, which is the core checker.

```c
void FUN_00403474(undefined4 *param_1)
{
  int iVar1;
  long lVar2;
  int local_14;
  long local_10;
  
  lVar2 = thunk_FUN_004010fe(param_1 + 3);
  if ((lVar2 == 0x3b) && (*(char *)((long)param_1 + 0x46) != '\n')) {
    do {
      iVar1 = FUN_007e1490();
      if (iVar1 == 10) break;
    } while (iVar1 != -1);
  }
  local_10 = thunk_FUN_004010fe(param_1 + 3);
  if ((local_10 != 0) && (*(char *)((long)param_1 + local_10 + 0xb) == '\n')) {
    *(undefined1 *)((long)param_1 + local_10 + 0xb) = 0;
    local_10 = local_10 + -1;
  }
  if (local_10 == 0x3b) {
    for (local_14 = 0; local_14 < 0x3b; local_14 = local_14 + 1) {
      *(undefined1 *)(param_1 + (long)local_14 * 3 + 0x21) =
           *(undefined1 *)((long)param_1 + (long)local_14 + 0xc);
      param_1[(long)local_14 * 3 + 0x22] = local_14;
      param_1[(long)local_14 * 3 + 0x23] = 0;
    }
    FUN_0040302d(param_1);
    *param_1 = 3;
  }
  else {
    FUN_007df430("nuh uh");
    *param_1 = 1;
  }
  return;
}
```

Inside `FUN_00402880`, we can see how validation works. First, the program builds a 59-byte target sequence from two resources:
- Calls `FUN_00402412(resource1, strlen(resource1), &len)` to generate a blob
- Then `FUN_0040254e(blob, len, scratch, resource3)` to convert it into the final target sequence

After that, it checks each position i from 0 to 58. The guess character is transformed through `FUN_00402061(ch, i, resource4)` then compared with `target[i]`. If equal, the triplet status remains 0; if not, status is set to 2.

```c
void FUN_00402880(long param_1,long param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5)
{
  ushort uVar1;
  int iVar2;
  undefined8 uVar3;
  undefined1 local_d8 [16];
  undefined1 local_c8 [16];
  undefined1 local_b8 [11];
  undefined5 uStack_ad;
  undefined1 auStack_a8 [11];
  char acStack_98 [60];
  uint local_5c;
  uint local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  uint local_44;
  uint local_40;
  uint local_3c;
  undefined1 local_38 [8];
  undefined8 local_30;
  char local_21;
  long local_20;
  undefined8 local_18;
  int local_c;
  
  iVar2 = FUN_007cc940(&DAT_00a54580);
  if (iVar2 == 0) {
    local_d8 = (undefined1  [16])0x0;
    local_c8 = (undefined1  [16])0x0;
    local_b8 = SUB1611((undefined1  [16])0x0,0);
    uStack_ad = 0;
    auStack_a8 = SUB1611((undefined1  [16])0x0,5);
    uVar1 = FUN_00401d85();
    local_3c = uVar1 ^ 0x12345678;
    local_40 = 0xdeadbfb4;
    uVar3 = thunk_FUN_004010fe(param_3);
    local_18 = FUN_00402412(param_3,uVar3,&local_30);
    local_44 = local_40 ^ local_3c;
    uVar1 = FUN_00401d85();
    local_48 = uVar1 ^ 0x12345678;
    local_4c = 0xdeadbf b0;
    local_20 = FUN_0040254e(local_18,local_30,local_38,param_5);
    local_50 = local_4c ^ local_48;
    for (local_c = 0; local_c < 0x3b; local_c = local_c + 1) {
      uVar1 = FUN_00401d85();
      local_54 = uVar1 ^ 0x12345678;
      local_58 = 0xdeadbf88;
      local_21 = FUN_00402061((int)*(char *)(param_1 + local_c),local_c,param_4);
      local_5c = local_58 ^ local_54;
      acStack_98[local_c] = local_21;
      if (acStack_98[local_c] == *(char *)(local_20 + local_c)) {
        *(undefined4 *)(param_2 + (long)local_c * 0xc + 8) = 0;
        local_d8[local_c] = 1;
      }
      else {
        *(undefined4 *)(param_2 + (long)local_c * 0xc + 8) = 2;
      }
    }
    FUN_007f27c0(local_18);
    FUN_007f27c0(local_20);
  }
  return;
}
```

Function `FUN_00402061` is simply a lookup into a 256-byte table just built for index i through `FUN_00401ef1`. That's where the cryptographic pattern is revealed:
- `FUN_00401ef1` generates a substitution table by creating a key string `"%s_pos_%d_v2"` combining "resource4" and index
- Hashing with a 32-byte hash (`FUN_00403b60`, likely SHA-256)
- Running Fisher–Yates shuffle on array 0..255 with swap index `j = (seed[(t*3)%32] * 256 + seed[t%32]) % (t+1)`

So, for each position, there's a different permutation that maps input byte to output byte. Validation simply checks if `table_i[guess[i]]` equals the target byte at that position.

```c
undefined1 FUN_00402061(byte param_1,undefined4 param_2,undefined8 param_3)
{
  undefined1 local_108 [256];
  
  FUN_00401ef1(param_2,param_3,local_108);
  return local_108[(int)(uint)param_1];
}

void FUN_00401ef1(undefined4 param_1,undefined8 param_2,long param_3)
{
  undefined8 uVar1;
  byte local_138 [32];
  undefined1 local_118 [259];
  undefined1 local_15;
  int local_14;
  int local_10;
  int local_c;
  
  FUN_007cfbb0(local_118,0x100,"%s_pos_%d_v2",param_2,param_1);
  uVar1 = thunk_FUN_004010fe(local_118);
  FUN_00403b60(local_118,uVar1,local_138);
  for (local_c = 0; local_c < 0x100; local_c = local_c + 1) {
    *(char *)(param_3 + local_c) = (char)local_c;
  }
  for (local_10 = 0xff; 0 < local_10; local_10 = local_10 + -1) {
    local_14 = (int)((uint)local_138[(local_10 * 3) % 0x20] +
                    (uint)local_138[local_10 % 0x20]) % (local_10 + 1);
    local_15 = *(undefined1 *)(param_3 + local_10);
    *(undefined1 *)(param_3 + local_10) = *(undefined1 *)(param_3 + local_14);
    *(undefined1 *)(local_14 + param_3) = local_15;
  }
  return;
}
```

In `FUN_0040390b` earlier, there's initialization of three local pointers to three global data symbols: `local_40 = &DAT_00a50120;`, `local_38 = &DAT_00a501d0;`, and `local_30 = &DAT_00a50200;`, likely the three required resources. This becomes a strong assumption because at `&DAT_00a501d0`, when XOR'ing back the first byte `0xF8 ^ 0xAB`, the result is `0x53` which is character 'S', followed by `0xC8 ^ 0xAB = 'c'`, `0xC3 ^ 0xAB = 'h'`, `0xCE ^ 0xAB = 'e'`, immediately revealing the prefix "Sche…"; XOR'ing the entire sequence until 00 produces `SchematicsCTF2025`.

![](../images/sch/flagle/Screenshot%202025-10-18%20235704.png)

With this, we can obtain three plaintext resources: `SchematicsCTF2025` as the table basis, custom alphabet for decoder (resource 3), and hexadecimal payload that after parsing produces the target (resource 1). The rest is to build per-index substitution tables from `"{SchematicsCTF2025}_pos_{i}_v2"` using SHA-256 as Fisher–Yates seed, then for each position find input byte x such that `table_i[x] == target[i]`. This is implemented with the following solver:

**solver.py**
```python
import hashlib
import re
import sys

RAW1_HEX = """9d 93 98 92 9d 92 9f 9f 9e 9d 9d 9f 9f 93 9f 92 98 93 9f 9e 9f c9 9e 98 9e 9d 9c 93 9d c9 99 cd 98 9b 9e 92 9c 92 9c 9c 9f 9e 9e 9f 9c 98 9d 9d 9e ca 9d c9 9c 9b 9f 9c 9f 98 98 9e 9f 98 98 9e 9c 93 9f cf 9e 9d 9e 92 98 99 9c 9b 9c 93 9d 9d 9d 9a 9d c8 9f cd 9d c9 9f 9d 9f 98 9f ce 9e 9f 9e 9b 9c ca 9d ce 9f cf 9e 9f 98 9d 9d cd 9f 99 9c 92 9d 9e 99 cd 9d c8 9c 9f 99 cd 9e 9c 9e 9b 98 93 9e 9d 9f cd 98 9d 9e 9f 98 98 9d 9a 98 9f 98 9d 9d 9f 9f 9f 9f 9d 9f 92 9c 9e 9f cd 98 cf 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00""".strip()
RAW2_HEX = """f8 c8 c3 ce c6 ca df c2 c8 d8 e8 ff ed 99 9b 99 9e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00""".strip()
RAW3_HEX = """ca c9 c8 cf ce cd cc c3 c2 c1 c0 c7 c5 c6 c4 db da d9 d8 df de dc dd d3 d2 d1 ea e9 e8 ef ee ed ec e3 e2 e1 e0 e7 e5 e6 e4 fb fa f9 f8 ff fe fc fd f3 f2 f1 9b 9a 99 98 9f 9e 9d 9c 93 92 80 84 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00""".strip()

def parse_hex(s: str) -> bytes:
    clean = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(clean) % 2 != 0:
        raise SystemExit()
    return bytes.fromhex(clean)

def xor(data: bytes, key=0xAB) -> bytes:
    out = bytearray()
    for b in data:
        if b == 0x00:
            break
        out.append(b ^ key)
    return bytes(out)

def custom_b64_decode(s: str, alphabet: str) -> bytes:
    if len(alphabet) != 64:
        raise SystemExit()
    idx = {ch:i for i,ch in enumerate(alphabet)}
    out = bytearray()
    s = "".join(ch for ch in s if not ch.isspace())
    i = 0
    while i < len(s):
        chunk = s[i:i+4]
        if len(chunk) < 4:
            break
        vals = []
        for ch in chunk:
            if ch == '=':
                vals.append(0)
            else:
                if ch not in idx:
                    raise SystemExit(f"{ch!r} not found")
                vals.append(idx[ch])
        v = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
        out.append((v >> 16) & 0xFF)
        if chunk[2] != '=':
            out.append((v >> 8) & 0xFF)
        if chunk[3] != '=':
            out.append(v & 0xFF)
        i += 4
    return bytes(out)

def build_table(i: int, kdf_base: str) -> bytes:
    key = f"{kdf_base}_pos_{i}_v2".encode()
    seed = hashlib.sha256(key).digest()
    a = list(range(256))
    # Fisher–Yates
    for t in range(255, 0, -1):
        j = (seed[(t*3) % 32] * 256 + seed[t % 32]) % (t + 1)
        a[t], a[j] = a[j], a[t]
    return bytes(a)

def main():
    res1_dec = xor(parse_hex(RAW1_HEX))  # ASCII hex
    res2_dec = xor(parse_hex(RAW2_HEX)).decode()  # "SchematicsCTF2025"
    res3_dec = xor(parse_hex(RAW3_HEX)).decode()  # custom alphabet

    # HEX -> bytes -> ASCII base64 string
    try:
        inner_b64 = bytes.fromhex(res1_dec.decode()).decode()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    # decode custom base64 then take first 59 bytes
    decoded = custom_b64_decode(inner_b64, res3_dec)
    target = decoded[:59]

    # invert table per-index: find x such that table_i[x] == target[i]
    flag = bytearray()
    for i in range(59):
        T = build_table(i, res2_dec)
        inv = [0]*256
        for idx, val in enumerate(T):
            inv[val] = idx
        flag.append(inv[target[i]])

    try:
        print(flag.decode("ascii"))
    except UnicodeDecodeError:
        print(flag.hex())

if __name__ == "__main__":
    main()
```

### Flag
SCH25{since_when_did_wordle_became_this_annoying__6675636b}
