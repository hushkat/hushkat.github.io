---
title: "DNA & Design"
date: 2024-11-29 01:09:33 +0300
author: [hushkat, mystique]
description: NextGenInCyber Writeups
image: /assets/images/GlacierCTF/afnextgenw.png
categories: [Crypto, Misc, Easy, GlacierCTF]
tags: [Crypto, Misc, Easy, GlacierCTF]
---
## DNA

The challenge provided this image:

![DNAENCRYPTED](/assets/images/GlacierCTF/DNA.png)


Extracted the string by reading the characters from left to right starting from the top going down. The resulting extracted string from the image: `TCATAGGCTAGCTACACTCGTTGTACACTAGACAGCTACACTCTCTGAAGCTAGCTATGAAGCGTCCTACTCCTATGA`

The challenge also has the following instructions 
`There are some pretty unusual encoding methods. Find the flag PS: Replace spaces with “_”`

From research this seems to be some kind of DNA type of encryption. I also learnt that I need to break the string into 3s, so that made it look like this:

`TCA TAG GCT AGC TAC ACT CGT TGT ACA CTA GAC AGC TAC ACT CTC TGA AGC TAG CTA TGA AGC GTC CTA CTC CTA TGA`

One of my team leads gave me this link that has mappings that could decode the above string. Managed to decode from [here](https://earthsciweb.org/js/bio/dna-writer/index.html?seq=CGTCTAATCATCTGTAGCGTCGATGACTGA#base_to_text)

The resulting string: `CTF DAHOMEY DANS TES GENES`

I then replaced the spaces (" ") with underscores as per the instructions, then embedded the flag prefix to the string.
`NGCCTF{CTF_DAHOMEY_DANS_TES_GENES}`

## DESIGN
This was yet another interesting misc challenge. We were presented with [this](https://drive.google.com/file/d/1zds3ymqwPkKuR8SXGeMiKuuKTr1gqoRb/view?usp=sharing) CSV file. The instructions simply asked:
`Can you sculpt me ?`
Opening the file using Microsoft Excel, we find a long list of values mapped in two columns labelled `X` and `Y`. Given the name of the challenge, file and instructions I immediately assumed that these might be image pixel coordinates. I therefore went ahead and asked chatGPT to come up with a python script that could reconstruct the image and it came up with this awesome script that did just that:
```
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

file_path = 'Art.csv'

# Step 1: Load and inspect the data
try:
    data = pd.read_csv(file_path)
    print("Column names:", data.columns)
except Exception as e:
    print(f"Error reading the file: {e}")
    exit()

# Step 2: Adjust column names as needed
if 'x' in data.columns and 'y' in data.columns:
    x_coords = data['x']
    y_coords = data['y']
elif 'X' in data.columns and 'Y' in data.columns:  # Example alternative
    x_coords = data['X']
    y_coords = data['Y']
else:
    print("Error: Could not find 'x' and 'y' columns in the file.")
    exit()

# Continue as before
max_x = x_coords.max()
max_y = y_coords.max()
image = np.zeros((max_y + 1, max_x + 1), dtype=np.uint8)
for x, y in zip(x_coords, y_coords):
    image[y, x] = 255
plt.imshow(image, cmap='gray')
plt.axis('off')
plt.show()
```

I then ran the script using the command:
```
pyhon3 image_reconstructor.py
```
Then managed to retrieve this image: 

![flag](/assets/images/GlacierCTF/Figure_1.png)

I therefore just added the flag prefix and submitted the final flag as: `NGCCTF{CTF_Navigating_the_Digital_Maze_4f8ae63f9}`
