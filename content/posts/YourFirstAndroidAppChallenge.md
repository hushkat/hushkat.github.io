\---

title: "Your First Android App: Beating Hextree Challenge 1 with the Debugger"
date: 2026-07-27
draft: false
description: "A beginner-friendly walkthrough of Hextree's Android Challenge 1."
tags: \["android", "mobile-security", "reverse-engineering", "beginner"]
categories: \["Android"]
showToc: true
---

If you're just getting started with Android app security, [Hextree's android-challenge1](https://github.com/hextreeio/android-challenge1) is a great first stop. It doesn't need Frida, Jadx, or any heavyweight reversing tools — everything you need is already sitting inside Android Studio. All we're going to do here is **read the source code carefully** and use the built-in **debugger** to skip past a couple of annoying checks.

Let's get into it.

## Setting up

Clone the repo and open it in Android Studio:

```bash
git clone https://github.com/hextreeio/android-challenge1
```

Once the project loads, the first place to look isn't the Java code — it's `AndroidManifest.xml`. This file tells you which screens (Activities) exist in the app, and which ones are allowed to be launched from outside the app.

```xml
<activity
    android:name=".FlagActivity"
    android:exported="false" />
<activity
    android:name=".ChallengeActivity"
    android:exported="false" />
<activity
    android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

So the app has three screens:

* **MainActivity** — the launcher screen, `exported="true"`, so this is the only one we can open directly.
* **ChallengeActivity** — internal, `exported="false"`.
* **FlagActivity** — internal, `exported="false"`.

Since the two interesting activities can't be triggered from outside the app, we'll have to earn our way into them from inside `MainActivity` itself.

## Stage 1: Getting past the counter

Opening `MainActivity.java`, this is the part that matters:

```java
TextView text = findViewById(R.id.main\_text);
text.setOnClickListener(new View.OnClickListener() {
    @Override
    public void onClick(View v) {
        counter++;
        text.setText("Counter: "+counter);
        if(counter>9999) {
            startActivity(new Intent(MainActivity.this, ChallengeActivity.class));
        }
    }
});
```

Every tap on the text view increments `counter`, and once it passes 9999, the app launches `ChallengeActivity`. Technically you *could* just tap the screen ten thousand times, but that's a great way to lose interest in Android security on day one. Instead, let's cheat — with the debugger.

The idea is simple: pause the app right at the line where `counter` gets incremented, manually change the value of that variable to something bigger than 9999, then let the app continue running as if nothing happened.

**Step 1 — Attach the debugger.** Click the debug icon (the little bug) in the top toolbar and wait for the app to install and launch on the emulator.

!\[Debugger attached to MainActivity, waiting on the Find the Flag screen](images/DebuggingApp.png)

**Step 2 — Set a breakpoint.** Click in the gutter next to the `counter++;` line so a red dot appears there. This tells the debugger to pause execution exactly when that line is about to run.

**Step 3 — Trigger it.** Tap the text view on the emulator once. The app will freeze at your breakpoint, and the **Threads \& Variables** tab at the bottom of Android Studio will show you the current value of `counter`.

**Step 4 — Override the value.** Right-click on `counter` in that panel and choose to set its value. Type in anything above 9999 — 10000 works fine.

!\[Setting the counter variable to 10000 from the debugger's Threads \& Variables panel](images/OverridingCounter.png)

**Step 5 — Resume.** Mute the breakpoint (so it doesn't keep stopping you) and hit Resume. The `if(counter>9999)` check now passes instantly, and the app jumps straight into `ChallengeActivity`.

!\[ChallengeActivity reached, showing ten buttons](images/ChallengeActivity.png)

## Stage 2: Picking the right button

`ChallengeActivity` throws ten buttons at you, and the code makes it look like a trap:

```java
View.OnClickListener failHandler = new View.OnClickListener() {
    @Override
    public void onClick(View v) {
        startActivity(new Intent(ChallengeActivity.this, MainActivity.class));
    }
};

findViewById(R.id.button1).setOnClickListener(failHandler);
findViewById(R.id.button2).setOnClickListener(failHandler);
findViewById(R.id.button3).setOnClickListener(failHandler);
findViewById(R.id.button4).setOnClickListener(failHandler);
findViewById(R.id.button5).setOnClickListener(failHandler);
findViewById(R.id.button6).setOnClickListener(failHandler);
findViewById(R.id.button7).setOnClickListener(failHandler);
findViewById(R.id.button8).setOnClickListener(failHandler);
findViewById(R.id.button9).setOnClickListener(new View.OnClickListener() {
    @Override
    public void onClick(View v) {
        startActivity(new Intent(ChallengeActivity.this, FlagActivity.class));
    }
});
findViewById(R.id.button10).setOnClickListener(failHandler);
```

Nine of the ten buttons just bounce you straight back to `MainActivity` (`failHandler`). Only **Button 9** has its own listener, and it's the only one that opens `FlagActivity` — the screen we actually want. No guessing required once you've read the code; just tap Button 9.

!\[FlagActivity reached after tapping Button 9, showing the seek bar and "The flag is here" hint](images/FlagctivityAfterButton9.png)

## Stage 3: Cracking the seek bar

`FlagActivity` hides the flag behind a `SeekBar` (a slider):

```java
int progressTracking = 0;

@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity\_flag);

    TextView text = findViewById(R.id.flag\_text);
    SeekBar bar = findViewById(R.id.seek\_bar);
    bar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
        @Override
        public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
            text.setText("Read the code: "+progress+"%");
            progressTracking = progress;
        }

        @Override
        public void onStartTrackingTouch(SeekBar seekBar) {
        }

        @Override
        public void onStopTrackingTouch(SeekBar seekBar) {
            if(progressTracking==42) {
                text.setText(decryptFlag());
            }
        }
    });
}
```

The flag only shows up if the slider's progress is **exactly 42%** at the moment you let go of it.

{{< alert "circle-info" >}}
Notice *where* that check lives: inside `onStopTrackingTouch`, not `onProgressChanged`. That means the comparison isn't happening while you're dragging the slider — it only fires the instant you release your finger (or mouse click) off the seek bar. Drag to 42%, and you can still overshoot it on release.
{{< /alert >}}

There are two ways to solve this: drag the slider around very carefully until you land on exactly 42%, or just use the debugger again. Let's go with the debugger — it's more reliable and, frankly, more satisfying.

**Step 1 — Breakpoint on the check.** Set a breakpoint on the `if(progressTracking==42)` line.

**Step 2 — Trigger it.** Drag the slider a bit and release it. Execution pauses right at your breakpoint.

**Step 3 — Override the variable.** In the Threads \& Variables panel, right-click `progressTracking` and set it to `42`, regardless of where the slider visually sits.

!\[progressTracking overridden to 42 in the debugger, even though the slider is at 81%](images/SetSliderTo42.png)

**Step 4 — Resume.** Mute the breakpoint, hit Resume, and the condition evaluates to true. `decryptFlag()` runs, and the flag is revealed on screen.

!\[The decrypted flag displayed on the FlagActivity screen](images/Flag.png)

## Wrapping up

That's the whole challenge:

1. **MainActivity** — override `counter` past 9999 in the debugger instead of tapping 10,000 times.
2. **ChallengeActivity** — read the code to find that only Button 9 leads anywhere useful.
3. **FlagActivity** — override `progressTracking` to exactly 42 to satisfy the `onStopTrackingTouch` check.

Nothing here needed decompiling an APK or writing a single line of exploit code — just reading the Java source closely and letting Android Studio's debugger do the boring work of "typing in the right number." That's honestly most of Android app security at the beginner level: the vulnerable logic is usually sitting in plain sight, and the debugger is one of the most underrated tools for proving it.

