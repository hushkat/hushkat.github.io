---
title: "BITSCTF 2025"
date: 2025-02-10T01:09:33+03:00
draft: false
description: "BITSCTF 2025 writeups covering welcome, OSINT, and DFIR challenges"
slug: "bitsctf-2025"
tags: ["WELCOME", "OSINT", "DFIR", "Easy", "BITSCTF"]
categories: ["CTF", "DFIR", "OSINT"]
showAuthor: true
showDate: true
showReadingTime: true
showWordCount: true
featureimage: "https://ctftime.org/media/cache/11/7f/117f00458b2384e62ad93857d88e7930.png"
---

# WELCOME - SANITY CHECK

This was an easy challenge to test the player's sanity. I joined the BITSCTF Discord server and found the flag.
![Discord Flag](/images/BITSCTF/SanityCheck.png)

# BABY DFIR - DFIR

This was an easy challenge in the DFIR category. The description read:
I promise this is actually easy.

A file `abc.ad1` was attached to the challenge. I downloaded the file and ran the head command on the file that actually suggested this might be some host machine image with just the file I am looking for:
```
head abc.ad1                               
ADSEGMENTEDFILEï¿½]ADLOGICALIMAGEuï¿½AD\ï¿½ï¿½C:\Users\vboxuser\DesktopC:\Users\vboxuser\Desktop]ï¿½ï¿½â¦
            desktop.iniï¿½ï¿½xï¿½ï¿½ï¿½K
                              aï¿½ï¿½ï¿½ï¿½3ï¿½â¦ï¿½eï¿½ï¿½ï¿½ï¿½K,&S3ï¿½\ï¿½x<ß"ï¿½Nï¿½ï¿½;ï¿½tï¿½ï¿½|Ô©ï¿½$bï¿½ï¿½ï¿½ï¿½â¦ï¿½ï¿½Ö„#;Jï¿½ï¿½ï¿½iï¿½ï¿½ï¿½q×»eï¿½ï¿½ï¿½rRIï¿½ï¿½ï¿½!#â¦nï¿½ï¿½^Ä…ï¿½ÒºÈ®ï¿½>|ï¿½vÅ¼ï¿½ï¿½ï¿½ï¿½&-QLï¿½.ï¿½ê‚‰)ï¿½7ï¿½ï¿½ï¿½JËœï¿½2ï¿½jï¿½w^L_Wï¿½zï¿½2ï¿½1ï¿½282ï¿½20falsetfalseï¿½trueï¿½trueï¿½trueï¿½falseï¿½true!P 9e36cc3537ee9ee1e3b10fa4e761045bP(7726f55012e1e26cc762c9982e7c6c54ca7bb303ï¿½ï¿½flag.txtï¿½ï¿½xï¿½sï¿½
                                                  	vqï¿½Nï¿½/JMï¿½É©ï¿½/ï¿½ï¿½-ï¿½Iï¿½ï¿½ï¿½+)Ê/Éwqï¿½
    ï¿½74ï¿½0ï¿½Hï¿½Lï¿½ï¿½|ï¿½147A20250206T225151.34814620250206T225125.094082ï¿½	20250206falseï¿½falseï¿½trueï¿½falsefalse*falseBtruevP 3677fb16caa7ba1e220668079cf26838P(035037471f31c918556e266b9bfc1bbd4c026ce5ATTRGUIDï¿½sØŠï¿½ï¿½jGï¿½â¦6ï¿½ï¿½ï¿½k
                                                         ï¿½5Lv!Gï¿½ï¿½ï¿½â¦3ï¿½7ï¿½ï¿½ï¿½CWOï¿½Ê€6ï¿½ï¿½ï¿½2ï¿½ï¿½Ã°Lï¿½S`tï¿½ï¿½ï¿½	~J_ï¿½Kï¿½ï¿½hï¿½ï¿½dï¿½dï¿½d:~Oï¿½2ï¿½(ï¿½ï¿½X
                                         EUBï¿½ï¿½Bï¿½ï¿½ï¿½ï¿½ï¿½Ayï¿½ï¿½ï¿½jï¿½=ï¿½Mï¿½sÜï¿½6^ï¿½ï¿½5bï¿½Eï¿½e.*`^ï¿½ï¿½ey\bCï¿½ï¿½ï¿½ZMq@P
3ï¿½kï¿½ï¿½Mï¿½>!ï¿½ï¿½ï¿½uPï¿½ï¿½@'#$Lï¿½Xï¿½êŸ¤ï¿½\eï¿½ï¿½^ï¿½Dï¿½ï¿½_Uï¿½LOCSGUID>ï¿½ï¿½ï¿½bIï¿½Dï¿½Xï¿½ï¿½hoï¿½  
```
So how then do I get to the `flag.txt` file? I downloaded FTK imager tool on my windows machine and used it to open the given file. That gave me access to the flag as illustrated below:
![FTK imager flag](/images/BITSCTF/BabyDFIR.png)

# HOT PAUSE - OSINT

The instructions were:

What even is OSINT about this?
nc chals.bitskrieg.in 8000

This is the video that was attached to the challenge. [Watch](https://gist.github.com/user-attachments/assets/80f68cbb-107c-49cd-8e16-1cf2124a7133)

I played it multiple times then proceeded to use exiftool to view its metadata and see if I could find any hints. I found nothing. I then ran the NC command and saw the first question, asking about what cityÂ that concert Â wasÂ in.
```
nc chals.bitskrieg.in 8000
Welcome secret agent. We've recovered a video from our aliases infiltrating our next target. Your first task is to find out what is our target city.
City Name (all caps):
```
I paused the video at a point where I felt was unique or peculiar:

![Hot Pause](/images/BITSCTF/Stage.png)

I  proceeded to use google lens to do a reverse image search and discovered that this was COLDPLAY music group  concert that happened in India at Ahmedabad at the NarendraÂ ModiÂ Stadium. 
The answer to the first question was AHMEDABAD. That was the name of the city where the concert happened. I submitted it and got a second question:

```
nc chals.bitskrieg.in 8000
Welcome secret agent. We've recovered a video from our aliases infiltrating our next target. Your first task is to find out what is our target city.
City Name (all caps): AHMEDABAD
Correct!
Well done! Now you need to find out where our partner agent was sitting.
Block Letter with Bay(For eg. A5,B1 etc.):
```
For this question I googled the sitting arrangement for the concert and found one useful one from [here](https://coldplayindia.com/best-seats-for-coldplay-ahmedabad-concert/):
![Hot Pause](/images/BITSCTF/image.png)

Visually inspecting the angle from where the video was taken and comparing to the image above, I had good reasons to think it was taken from section Q. I bruteforced the answer till Q3 got accepted. After submitting it, I got another question:
```
nc chals.bitskrieg.in 8000
Welcome secret agent. We've recovered a video from our aliases infiltrating our next target. Your first task is to find out what is our target city.
City Name (all caps): AHMEDABAD
Correct!
Well done! Now you need to find out where our partner agent was sitting.
Block Letter with Bay(For eg. A5,B1 etc.): Q3
Correct!
Good work. Now when you hear Chris Martin say "You know I love you so...." for the beat drop, I need you to use your Flipper Zero to send the correct data stream, replicating the wristbands colour exactly. Our enemies should have no clue. Good Luck.
DataÂ Stream:
```
At first I thought I was colorblind, I tried submitting white, it didn't work, then tried yellow and orange and it also didnt work. I asked a teammate for help then he sent me to go do some reading in [this](https://github.com/danielweidman/pixmob-ir-reverse-engineering/blob/main/README.md) github repository.
While there I found [this](https://github.com/danielweidman/flipper-pixmob-ir-codes/blob/main/pixmob_all_colors.ir) specific page where I picked the stream bits for the color yellow:
```
1400 1400 700 700 700 700 1400 2800 700 2100 700 700 700 1400 700 1400 1400 2800Â 1400Â 2800Â 700
```
I then submitted this as the last answer and was given the flag:
```
nc chals.bitskrieg.in 8000
Welcome secret agent. We've recovered a video from our aliases infiltrating our next target. Your first task is to find out what is our target city.
City Name (all caps): AHMEDABAD
Correct!
Well done! Now you need to find out where our partner agent was sitting.
Block Letter with Bay(For eg. A5,B1 etc.): Q3
Correct!
Good work. Now when you hear Chris Martin say "You know I love you so...." for the beat drop, I need you to use your Flipper Zero to send the correct data stream, replicating the wristbands colour exactly. Our enemies should have no clue. Good Luck.
DataÂ Stream: 1400 1400 700 700 700 700 1400 2800 700 2100 700 700 700 1400 700 1400 1400 2800 1400 2800 700
Correct!

Good Job agent. Here's your flag, should you choose to accept it: BITSCTF{that_was_a_very_weird_OSINT_challenge_afd12df}
```

---
