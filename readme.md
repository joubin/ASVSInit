# ASVSInit
## Intro
ASVS Init is a simple project that maps ASVS sections to OWASP Top 10 (bridging it from CWEs).

It then creates artifacts that can be tracked with your project though your DevSecOps journey.

## Running it.

```bash
python3 Stage.py

```

Running the above command will generate the `init` folder that should be tracked with your project. For simplicty, it also includes all of the shield/badges required thanks to (shields.io)[https://shields.io].

```bash
joubin@MBP ~/Git/ASVSInit % tree init
init
├── 1.1.1.md
├── 1.1.2.md
├── 1.1.3.md
├── 1.1.4.md
├── 1.1.5.md
├── 1.1.6.md
├── 1.1.7.md


```

Simply move the `init` folder to your code repository and work on each activity as it fits with your project. Then capture the results in the appropriate `markdown` file.

![Screen Shot 2020-02-09 at 4 07 11 PM](https://user-images.githubusercontent.com/1058767/74113071-a7a37700-4b56-11ea-8086-9dc88f9344bf.png)



That's it. Now you can track your security as you go along.
