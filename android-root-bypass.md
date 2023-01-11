# Bypassing root detection on Android #

_Jan. 10, 2023_

I've recently had to install a banking app on my Xiaomi Redmi 7. Upon launching it, I was greeted by "Sorry, this app doesn't support rooted devices".

Welp, that sucks. My phone is not strictly "rooted", but I did unlock the bootloader and install a custom Android 10 ROM.

I then had to undergo the big quest of "how to bypass application root check on android". Turns out it's fairly easy.. If you know what to do. If you don't though, enjoy the google results from 5 years ago, the outdated guides and the not-quite-my-problem threads on xda that lead you nowhere anyway. The world of Magisk and defeating SafetyNet moves fast.

So for january 2023, here's what I had to do to get it to work:

* Install [Magisk](https://github.com/topjohnwu/Magisk/releases) (v25.2) and the following modules:
    * [Universal SafetyNet Fix](https://github.com/kdrag0n/safetynet-fix/releases) (v2.4.0)
    * [Shamiko](https://github.com/LSPosed/LSPosed.github.io/releases) (v0.6)
    * [MagiskHidePropsConf](https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf/releases) (v6.1.2)
* Enable Zygisk in Magisk
* Add my banking app to Magisk's DenyList. I didn't need to check "Enforce DenyList" or add any other app to it.

Fortunately Magisk has a [very good installation guide](https://topjohnwu.github.io/Magisk/install.html). Turns out my phone was one of those that report "Ramdisk: No" even though it worked just fine to patch boot.img. Also, the optional step to reflash vbmeta.img bootlooped my phone, so I had to re-reflash it without the fastboot arguments; in any case, it is indeed optional.

For MagiskHidePropsConf, I had to run it in a root shell (the command is "props") and configure the whole shebang - 1/Fingerprint, 2/BASIC keys, 4/props. It is my understanding that you don't need this step (maybe even the entire module) if you only rooted your phone but kept the stock ROM.
