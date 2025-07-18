---
title: "SheetsNLayers"
date: 2024-11-24 01:09:33 +0300
author: [hushkat]
description: P3rf3ctr00t CTF Writeups
image: /assets/images/PerfectRoot/SheetsNLayers/PerfectRootLogo.png
categories: [Misc, PerfectRoot]
tags: [Misc, Easy, PerfectRoot]
---

This was a 4-part series of challenges linked to each other. I will explain my approach on solving the challenge below as I captured the first to last flag in that series.

## SheetsNLayers1
What is flag 1?

We are given a file to download which happened to be a zip file. 
![TaskFile](/assets/images/PerfectRoot/SheetsNLayers/TaskFile.png)
I went ahead to unzip the file and found a `SheetsNlayers.vhdx` file, this is a file format used for virtual hard disks. I then mounted the disk on my host machine to explore it further.
![Flag1 Files](/assets/images/PerfectRoot/SheetsNLayers/Flag1&Files.png)
I noticed that it contained three more files, one which just happens to be our first flag, so on opening it, this is what I found: `=03YkNTNlNzYjZjYmVGMmFWZ4MTO1QWY0AzM0MmNhdjMzsHdwAjc`. Looks like a Base64 encoded string. I decoded this string from [dcode](https://www.dcode.fr/base-64-encoding) and noticed that it was in reversed form, giving us the flag: `r00t{327a6c4304ad5938eaf0efb6cc3e53dc}` This has been illustrated below:
![Flag1](/assets/images/PerfectRoot/SheetsNLayers/Flag1.png)

## SheetsNLayers2
What is flag 2?
![TaskFile](/assets/images/PerfectRoot/SheetsNLayers/Task2.png)

Now that we found flag 1, its time to further explore the rest of the files and see what we can find. I started by reading the note that was present in the disk we accessed. What I found there was this text: `This next archieve contains more flags. Unfortunately the file looks preety blank to me and i can't seem to get all flags. (flag-2 , flag-3, flag-4) Good luck.` So I immediately tried to access the archive called `moreflags.zip` but I couldnt, since it had a password. It was therefore time to start cracking using `JohnTheRipper` by using the following commands on a unix terminal:
```
zip2john moreflags.zip > moreflags.hash #To extract the archive's hash
#The output:
ver 2.0 moreflags.zip/moreflags/ is not encrypted, or stored with non-handled compression type
ver 2.0 moreflags.zip/moreflags/moreflags.xlsx PKZIP Encr: cmplen=10742, decmplen=15277, crc=BADB9879 ts=B4AB cs=badb type=8
                                                                                                                                                                                                                                            
john --wordlist=/usr/share/wordlists/rockyou.txt moreflags.hash #Cracking the hash with the rockyou wordlist
#The output:
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
No password hashes left to crack (see FAQ)

john moreflags.hash --show #To see the cracked hash
#The output:
moreflags.zip/moreflags/moreflags.xlsx:ne.11.88:moreflags/moreflags.xlsx:moreflags.zip::moreflags.zip

1 password hash cracked, 0 left
```
Notice that we manage to get the password to the archive as shown in the output above: `ne.11.88` I then used this password to access the archive. What I found in the archive was an excel sheet with the name: `moreflags.xlsx`. On opening the file, It seemed blank at first sight. But then I right-clicked sheet 1 and clicked unhide, and found 3 more hidden sheets. So I retrieved them one after another with the same process as illustrated below:
![HiddenSheets](/assets/images/PerfectRoot/SheetsNLayers/UnhidingSheets.png)
On opening the flag 2 sheet, I found the flag in an encrypted format:
![Flag2Encrypted](/assets/images/PerfectRoot/SheetsNLayers/Flag2Encrypted.png)
I then copied the flag text and headed to cyberchef where I managed to successfully decode the flag from base85 to plain text as illustrated below:
![Flag2Decrypted](/assets/images/PerfectRoot/SheetsNLayers/Flag2.png)
I managed to capture my second flag ~ `r00t{df38bae72ccf3f172345dcee96a7ea21}`

## SheetsNLayers3
What is flag 3?
![TaskFile](/assets/images/PerfectRoot/SheetsNLayers/Task3.png)

Moving on to task 3, I open sheet 3 trying to find the third flag. 
![Flag3Encrypted](/assets/images/PerfectRoot/SheetsNLayers/Flag3Encrypted.png)
I find it sitting right there, but it seems encoded once again. I therefore click on the first cell and copy the text in that cell, which happened to be:
`flag3 - TVRFMElEUTRJRFE0SURFeE5pQXhNak1nTlRZZ05UVWdPVGtnT1RnZ09Ua2dPVGNnTlRRZ05Ea2dOVGNnTlRFZ05UVWdNVEF4SURFd01TQXhNREVnTlRRZ05UQWdORGdnTlRZZ05Ea2dOVEFnTVRBeUlEVTNJREV3TVNBMU5pQXhNREVnTlRNZ09Ua2dOVE1nTlRFZ01UQXdJRFE0SURRNElERXlOUT09 TVRFMElEUTRJRFE0SURFeE5pQXhNak1nTlRZZ05UVWdPVGtnT1RnZ09Ua2dPVGNnTlRRZ05Ea2dOVGNnTlRFZ05UVWdNVEF4SURFd01TQXhNREVnTlRRZ05UQWdORGdnTlRZZ05Ea2dOVEFnTVRBeUlEVTNJREV3TVNBMU5pQXhNREVnTlRNZ09Ua2dOVE1nTlRFZ01UQXdJRFE0SURRNElERXlOUT09 TVRFMElEUTRJRFE0SURFeE5pQXhNak1nTlRZZ05UVWdPVGtnT1RnZ09Ua2dPVGNnTlRRZ05Ea2dOVGNnTlRFZ05UVWdNVEF4SURFd01TQXhNREVnTlRRZ05UQWdORGdnTlRZZ05Ea2dOVEFnTVRBeUlEVTNJREV3TVNBMU5pQXhNREVnTlRNZ09Ua2dOVE1nTlRFZ01UQXdJRFE0SURRNElERXlOUT09` 
Looking at it closely, I noticed, its the same text, repeated thrice. I therefore did some cleaning by removing the prefix `flag3 - ` then followed to remove two of the repitions and headed back to cyberchef to see if I could decrypt the text and obtain the flag. As shown below, it was encrypted more than once, but once again, I was able to decode it with the help of Cyberchef and got the flag for this challenge:
![Flag3Decrypted](/assets/images/PerfectRoot/SheetsNLayers/Flag3.png)
Third flag ~ `r00t{87cbca61937eee620812f9e8e5c53d00}`

## SheetsNLayers4
What is flag 4?
![TaskFile](/assets/images/PerfectRoot/SheetsNLayers/Task4.png)

After solving the last three challenges in this series, I finally got to the last one. I thought to myself, that this is probably going to be as easy as the first three, only to open the sheet and see alot of "blood" with "no comments". Just see for yourself:
![NoComments](/assets/images/PerfectRoot/SheetsNLayers/RedNoComment.png)
Anyway I decided to first deal with the "blood", I set the whole sheet to white then started looking for more clues. Immediately I saw a cell that stood out and decided to hover my cursor over it and once again, the flag was right there. Use your eyes once again, they say seeing is believing:
![Flag4Encrypted](/assets/images/PerfectRoot/SheetsNLayers/Flag4Encrypted.png)
Let's try and decode it (This time though, CyberChef didnt help so I went back to dcode) The encryption was identified as ROT47 and decoded successfully as shown below:
![Flag4Decrypted](/assets/images/PerfectRoot/SheetsNLayers/Flag4.png)
That gave me the last flag for the challenge ~ `r00t{87cbca61937eee620812f9e8e5c53d00}`

