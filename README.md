# cppRecall

PoC aimed to dump the (unencrypted) database from the Microsoft Recall folder to extract sensitive information and screenshots.

Based on [this](https://github.com/xaitax/TotalRecall/tree/main) repository from [xaitax](https://github.com/xaitax), I thought I'd make a compiled version so that it can be ran on a Windows host even when the Python interpreter is not installed.

## How to compile
You can find a pre-compiled binary for ARM64 in the release tab or [here](https://github.com/otterpwn/cppRecall/blob/main/cppRecall/ARM64/Release/cppRecall.exe).
If you want to build this on your own open the `.sln` file in Visual Studio, make sure to have the ARM and ARM64 compilers and libraries installed (you can follow [this](https://blogs.windows.com/windowsdeveloper/2018/11/15/official-support-for-windows-10-on-arm-development/) guide to set those up).

## Usage
For now the tool doesn't support any arguments and can be ran normally
```
.\cppRecall.exe
```
This will execute the binary targeting the Recall folder for the current user and dumping **ALL** the data inside the database and ImageStore folder.

In the future I intend to add CLI arguments that will allow to manually specify the username and a range of timestamps to include.

## Results
After running this script you'll be able access the dumped text and images from the dump folder name with the `<TIMESTAMP>_Recall_Extraction` format.

- Text file

![](https://github.com/otterpwn/cppRecall/blob/main/assets/results_txt.png)

- Image folder

![](https://github.com/otterpwn/cppRecall/blob/main/assets/results_image.png)

Since the binary is not performing any inherently malicious tasks but it's just reading a single unencrypted file it probably won't need any obfuscation or packing when going up against more common AV solutions.

![](https://github.com/otterpwn/cppRecall/blob/main/assets/vt_results.png)
