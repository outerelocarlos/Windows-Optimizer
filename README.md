# Windows Optimizer

Powershell project to optimize Windows by debloating and improving its default user experience, featuring several premade presets and tweaks to customize Windows at user's will.

## Contents

* [Description](#description)
* [Usage](#usage)
* [Premades](#premades)
* [FAQ](#faq)
* [Windows builds overview](#windows-builds-overview)
* [Advanced usage](#advanced-usage)
* [Maintaining own forks](#maintaining-own-forks)
* [Contribution guidelines](#contribution-guidelines)
* [Documentation](#documentation)

  * [Setup](#setup)
  * [O&O ShutUp10 Setup](#oo-shutup10-setup)
  * [Privacy Tweaks](#privacy-tweaks)
  * [UWP Privacy Tweaks](#uwp-privacy-tweaks)
  * [Security Tweaks](#security-tweaks)
  * [Network Tweaks](#network-tweaks)
  * [Service Tweaks](#service-tweaks)
  * [UI Tweaks](#ui-tweaks)
  * [Explorer UI Tweaks](#explorer-ui-tweaks)
  * [Application Tweaks](#application-tweaks)
  * [Server Specific Tweaks](#server-specific-tweaks)
  * [Unpinning](#unpinning)
  * [Finishing Functions](#finishing-functions)
  * [Current issues](#current-issues)

<br>

## Description

This project uses PowerShell scripting to debloat and improve the default Windows experience. It is built upon [Disassembler's work](https://github.com/Disassembler0/Win10-Initial-Setup-Script), continuing and improving it in many ways: some of his functions were modified, some new functions have been implemented and various premade presets and tweaks have been provided.  
It is also possible (and easy) to edit any of the provided presets and/or tweaks to customize the selected functions, creating a preset and/or tweak of your own.

The project is fully automated and does not require user input (albeit for the `WaitForY` and `DisableLogin` functions, which can be commented), something Windows system administrators are likely to appreciate.

Note that the project is a never-ending WIP (Work In Progress). If you encounter any errors/problems, please raise an issue via GitHub or drop me a mail at outerelocarlos@gmail.com

You can also show your appreciation via [PayPal](https://paypal.me/outerelocarlos) and/or [Ko-fi](https://ko-fi.com/outerelocarlos).

### Requirements

Having a Windows-based system and Internet connection. More information regarding the Windows versions supported by this project can be found in the [FAQ](#faq).

Make sure your account is a member of the *Administrators* group as the script attempts to run with elevated privileges. Standard users will get an UAC prompt asking for admin credentials which then causes the tweaks to be applied to the given admin account instead of the original non-privileged one. This can be circumvented by uncommenting the `RequireAdmin` function, but most tweaks will output an error.

<br>

## Usage

[Download and unpack the source code](https://github.com/outerelocarlos/Windows-Optimizer/archive/refs/heads/master.zip) or the [latest release](https://github.com/outerelocarlos/Windows-Optimizer/releases), find the premade preset or tweak that fits your needs the most (or customize your own) and then simply right-click on it and select the **Run as administrator** option (confirm the *User Account Control* prompt if asked to).

Make sure your account is a member of the *Administrators* group as the script attempts to run with elevated privileges. Standard users will get an UAC prompt asking for admin credentials which then causes the tweaks to be applied to the given admin account instead of the original non-privileged one. This can be circumvented by uncommenting the `RequireAdmin` function, but most tweaks will output an error.

The process of customizing tweaks and presets has been streamlined so that users can easily create their own. For more information on the subject, refer to the [Advanced usage](#advanced-usage) section.

<br>

## Premades

### Premade Presets

Multiple premade presets were built so that users can choose whichever one fits their needs the most without having to modify files too much or at all. Each preset is but a list of functions which are to be called (unless commented). These presets are stored in four folders, two for each of the targeted Windows versions:

* **Custom Presets**: tailor-made presets for myself, family and friends (you could fork the project and host your preset within this folder).

* **Presets**: the generalized and recommended presets. There are 3 different levels, each with a laptop and desktop variant:
  
  * **Level 1 - Basic**: debloats and improves the default Windows experience (both in usability and privacy-wise) while being as safe to use as possible.
  
  * **Level 2 - Recommended**: expands upon the **Basic** preset with the use of [O&O ShutUp10](https://www.oo-software.com/shutup10) to further improve the default privacy settings. It also removes unessential Microsoft software and even core telemetry components (which might lead to some issues updating Windows down the line, in which case temporarily re-enable telemetry with the provided [premade tweak](#premade-tweaks)).
  
  * **Level 3 - Advanced**: expands upon the **Recommended** preset with some tweaks aimed towards power users, removing most of Microsoft's annoyances and reducing the security prompts and blocks that power users do not really need.

Note that there is an extra preset, named **Blank Template**, which is provided so that users can easily create their own custom presets (just edit the `.preset` file and comment/uncomment the functions of your choice). This template is the ideal choice to fine-tune Windows systems given that all the tweaks are commented by default (meaning that the only functions taking place are those uncommented by the user), but any premade preset can be edited and build upon to create a custom one (refer to the [Advanced usage](#advanced-usage) section for more details). 

### Premade Tweaks

Various easy-to-apply tweaks have been provided so that users can fine-tune their systems without having to modify a preset or mess around with command line options. These are stored within the [Tweaks](/Tweaks) folder and behave as follows:

* **Bloatware Uninstaller**: 
  * **Level 1**: uninstalls most third-party developed bloatware (crappy software that takes a toll on system resources).
  * **Level 2**: uninstalls most third-party developed bloatware and unessential Microsoft developed software. Some programs are left installed since some users make use of them (e.g. the Windows Calculator) but the most annoying or unneeded applications are removed (if needed, one can always install them back via the Microsoft Store).
  * **Level 3**: uninstalls as many pre-installed programs as possible, both from Microsoft and third-party developers. Some of the uninstalled software is actually useful and used by most people, so most users should run an alternative bloatware uninstaller level (although any missing software can be re-installed via the Microsoft Store).

* **Disable Indexing / Enable Indexing**: disables (or re-enables) file indexing, which can be too demanding of old HDD drives (leading to 100% usage).

* **Disable Login / Enable Login**: disables (or re-enables) user login at system boot, when waking up the system and when waking up from screen saver mode.

* **Disable Network Discovery and file sharing / Enable Network Discovery and file sharing**: disables (or re-enables) Network discovery and file/printer sharing, allowing or disallowing the computer to find and interact with other computers and devices on the network, sharing files and printers remotely.

* **Disable OneDrive / Enable OneDrive**: disables (or re-enables) and removes (or reinstalls) OneDrive from the system.

* **Disable Security Prompts and Blocks / Enable Security Prompts and Blocks**: sometimes Microsoft protects the user through security prompts, even going as far as blocking a given download if Defender does not trust its content or origins. This tweak collection disables (or enables) those security features.

* **Disable Telemetry (Level 1) / Enable Telemetry (Level 1)**: this tweak collection disables (or re-enables) user data collection from Microsoft. It does not completely get rid of it, since that is impossible, but strongly reduces it (as safely as possible to avoid issues with Windows).

* **Disable Telemetry (Level 2) / Enable Telemetry (Level 2)**: this tweak collection disables (or re-enables) user data collection from Microsoft. It does not completely get rid of it, since that is impossible, but removes most of it (while still prioritizing usability). Since it removes core telemetry components, there might be some issues updating Windows down the line, in which case temporarily re-enable telemetry with the provided premade tweak.

* **Disable Telemetry (Level 3) / Enable Telemetry (Level 3)**: this tweak collection disables (or re-enables) user data collection from Microsoft. It does not completely get rid of it, since that is impossible, but removes as much of it as possible (sacrificing usability if needed). Only recommended in those cases where privacy is the top priority.

* **Disable Windows 11 TPM requirement / Enable Windows 11 TPM requirement**: as of time of writing, installing Windows 11 requires TPM 2.0, a security feature of recent CPU architectures. This tweak disables (or re-enables) that requirement so that older systems can update their Windows 10 systems to Windows 11.

* **Repair Windows**: this preset runs "sfc /scannow" to inspect all of the important Windows files on the system, including Windows `.dll` files. If there exists a problem with any of these protected files, it/they will be replaced.

* **Restore Missing Power Plans**: useful for those scenarios where Windows does not automatically install the default power plans. Do not apply otherwise since it might lead to duplicate power plans.

Some premade Windows 11 UI tweaks have also been provided inside [a dedicated folder](/Premade%20Tweaks/Windows%2011%20UI%20Tweaks).

* **Disable Explorer Compact View / Enable Explorer Compact View**: disables or enables the classic "Compact view" for the Windows Explorer (the alternative is the more spaced view of Windows 11).

* **Disable Explorer Ribbon Bar / Enable Explorer Ribbon Bar**: disables or enables the classic "Ribbon bar" for the Windows Explorer (the alternative is the default Windows 11 top bar, which is more clean albeit less utility-centric).

* **Set Classic Context Menu / Set Modern Context Menu**: sets the context menu style (the classic is the original Windows 10 context menu, the modern is the much simpler Windows 11 one).

* **Set Start Menu Left / Set Start Menu Center**: sets the start menu position.

* **Set Windows 10 Style / Set Windows 11 Style**: these presets modify the Windows 11 appearance to resemble the Windows 10 UI or the default Windows 11 one (respectively).

<br>

## FAQ

**Q:** Can I run the presets/tweaks safely?  
**A:** This project and all of its associated scripts modify several registry keys and system settings with administrator privileges, meaning that all presets/tweaks have the means to break your system. As such, you should not use this project unless you understand its behavior and/or are willing to take that leap of faith.  
I have tested all of the functions thoroughly and have not found any issues with their behavior. Note that all presets create a restore point before modifying anything so that users can easily revert to the original state if any issues arise.  
Having said that, beware that **I'm not responsible for any broken systems.**  
Use this project at your own risk.

**Q:** Can I run the presets/tweaks repeatedly?  
**A:** Yes, and it is arguably recommended to do so since certain Windows updates reset some of the settings back to their default value. I actually run my personal preset as a scheduled task.

**Q:** Which versions and editions of Windows are supported?  
**A:** The project aims to be fully compatible with the most up-to-date 64bit version of Windows 10 and Windows 11 receiving updates from the semi-annual channel. Selected functions aside, the project should also work with LTSB/LTSC versions and 32bit systems since their core is basically identical. However, some tweaks rely on group policy settings so there may be a few limitations for Home and Education editions.

**Q:** Does the project support Windows Server 2016 or 2019?  
**A:** Yes, not only is Windows Server supported but some functions have been designed with the Server environment as their target.

**Q:** Does the project support Windows Server 1909, 20H2 or 2022?  
**A:** I have not had the chance to test those versions out, but they are deeply similar to Windows Server 2016 and 2019 so most functions should work as intended.

**Q:** Does the project support Windows 7, 8, 8.1 or any other older version of Windows?  
**A:** It does not. The project is primarily designed for Windows 10, Windows 11 and Windows Server. Some tweaks may work on older versions of Windows, but these versions are not officially supported. Since they have not been tested, some specific tweak might have an unexpected and undesirable outcome, so use at your own risk.

**Q:** Can I run the scripts in multi-user environment?  
**A:** Yes, to certain extent. Some tweaks (most notably UI tweaks) are set only for the user currently executing the script. As previously stated, the script can be run repeatedly and therefore it's possible to run it multiple times, each time as a different user.  
Note that, due to the nature of authentication and privilege escalation mechanisms in Windows, only users belonging to *Administrators* group can successfully apply most tweaks. Standard users will get an UAC prompt asking for admin credentials which then causes the tweaks to be applied to the given admin account instead of the original non-privileged one. This can be circumvented by uncommenting the `RequireAdmin` function, but most tweaks will output an error.  
There are more/better ways this can be circumvented programmatically, but I'm not planning to include any as it would negatively impact code complexity and readability. If you still wish to try to use the script in multi-user environment, check [this comment](https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/29#issuecomment-333040591) for some pointers.

**Q:** Did you test the presets/scripts?  
**A:** Yes, I have tested the scripts with several 64bit Windows editions in both virtual machines and home PCs, using whichever errors I could find to fine-tune the script. In fact, I have developed a few testers which can be found in the [Custom Presets](/Custom%20Presets) folder.

**Q:** I've run a script and it did something I don't like, how can I undo it?  
**A:** There is an opposite function for every tweak which undoes whichever registries and settings were modified by said tweak/function. Alternatively, since most functions are just automation for actions which can be done using GUI, one can easily search the net for an easy-to-follow solution guide.  
It is also worth noting that all presets create a restore point before modifying anything, meaning that users can easily revert to the original state if any issues arise.

**Q:** I've run a script and some controls are now greyed out and display the following message "*Some settings are hidden or managed by your organization*".  
**A:** To ensure that system-wide tweaks are applied smoothly and reliably, some of them make use of *Group Policy Objects* (*GPO*). The same mechanism is employed also in companies managing their computers in large scale, so the users without administrative privileges can't change the settings. If you wish to change a setting locked by GPO, apply the appropriate restore tweak and the control will become available again. [There easier solutions around though](https://youtu.be/E4arEKkEsuQ), although I have not tested them myself.  
I might look into which functions lead to this inconvenience in order to avoid it if possible. Please notify me (outerelocarlos@gmail.com) if you identify one of such functions.

**Q:** The project has broken my computer / killed neighbor's dog / caused World War 3.  
**A:** I have tested all of the functions thoroughly and have not found any issues with their behavior. What's more: all presets create a restore point before modifying anything so that users can easily revert to the original state if any issues arise. However, every system is built differently and, as was previously stated, you should not use this project unless you understand what its functions do and/or are willing to take that leap of faith.  
**I'm not responsible for any broken systems**, so use this project at your own risk.

**Q:** I'm using a tweak for &lt;feature&gt; on my installation, can you add it?  
**A:** Submit a PR, create a feature request issue or drop me a message/email (outerelocarlos@gmail.com). If I find the functionality simple and/or useful, I might add it.

**Q:** Can I use this project or modify its presets/tweaks for my and/or my company's needs?  
**A:** Sure, but beware of the copyright licenses. Disassembler's work [is licensed under MIT](./MIT-LICENSE.md) whereas any and all changes performed upon his/her work [are licensed under GPL3](./GPL3-LICENSE.md). His functions and contributions have been meticulously isolated in the `Core.ps1` and `Functions.psm1` files, everything else cannot be close-sourced as per [GPL3 license restrictions](./GPL3-LICENSE.md).  
If you modify and/or fork this project you must include copyright notice as per both licenses' requirements, and should also include a link to this GitHub repository since it is likely that something will be changed, added or improved to keep track with future versions of Windows 10 and Windows 11.

**Q:** Why are there repeated pieces of code throughout some functions?  
**A:** So you can directly take a function block or a line from within a function and use it elsewhere without elaborating on any dependencies.

**Q:** For how long are you going to maintain the project?  
**A:** I will do my best to keep this project alive for as long as there is a Windows version worth tweaking, but it will all depend on how much time I find to do so.

**Q:** I really like this project. Can I send a donation?  
**A:** Feel free to send donations via PayPal to [myself](https://www.paypal.me/outerelocarlos) or to [Disassembler](https://www.paypal.me/Disassembler), who developed the project upon which this one is built. Any amount is appreciated, but keep in mind that donations are completely voluntary.  
I have a [Ko-fi page](https://ko-fi.com/outerelocarlos) if that is more up your alley, and you can also send me a mail at **outerelocarlos@gmail.com** to discuss alternative methods.

<br>

## Windows builds overview

### Windows 10

| Version | Code name               | Marketing name       | Build |
|:-------:| ----------------------- | -------------------- |:-----:|
| 1507    | Threshold 1 (TH1 / RTM) | N/A                  | 10240 |
| 1511    | Threshold 2 (TH2)       | November Update      | 10586 |
| 1607    | Redstone 1 (RS1)        | Anniversary Update   | 14393 |
| 1703    | Redstone 2 (RS2)        | Creators Update      | 15063 |
| 1709    | Redstone 3 (RS3)        | Fall Creators Update | 16299 |
| 1803    | Redstone 4 (RS4)        | April 2018 Update    | 17134 |
| 1809    | Redstone 5 (RS5)        | October 2018 Update  | 17763 |
| 1903    | 19H1                    | May 2019 Update      | 18362 |
| 1909    | 19H2                    | November 2019 Update | 18363 |
| 2004    | 20H1                    | May 2020 Update      | 19041 |
| 20H2    | 20H2                    | October 2020 Update  | 19042 |
| 21H1    | 21H1                    | May 2021 Update      | 19043 |
| 21H1    | 21H2                    | November 2021 Update | 19044 |

### Windows 11

| Version | Code name               | Marketing name       | Build |
|:-------:| ----------------------- | -------------------- |:-----:|
| 21H2    | 21H2                    | N/A                  | 22000 |

<br>

## Advanced usage

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Core.ps1" [-include filename] [-preset filename] [-log logname] [[!]tweakname]
    
    -include filename       load module with user-defined tweaks
    -preset filename        load preset with tweak names to apply
    -log logname            save script output to a file
    tweakname               apply tweak with this particular name
    !tweakname              remove tweak with this particular name from selection

### Custom tweaks and presets

The `-include` parameter allows PowerShell to read custom function libraries/modules. At least one library is required for the script to work, otherwise no function/tweak can be called upon. Two libraries are included with the project by default, but users are welcome to create and use custom modules (more on this later).  
The included libraries are the following:

- **Functions.psm1**: the original functions/tweaks provided by Disassembler within its project.
- **Functions_Upgrade.psm1**: this library is not only an improvement over some of the original functions/tweaks (updating and overriding their behavior) but also features new functions/tweaks that expand upon the original script' scope.

Note that although the project is built around presets, each containing multiple functions/tweaks, these functions/tweaks are independent of said presets and can work as such (meaning that one can pass function names directly as arguments without them needing to belong within a preset). In fact, that is how the provided premade tweaks were built (these are actually tweak collections, meaning that more than one function is called upon). As an example, here's what the `Disable Indexing.cmd` file looks like:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Core.ps1" -include "Functions.psm1" -include "Functions_Update.psm1" - include "Functions_Expansion.psm1" DisableIndexing WaitForY Restart

The tweak names can be prefixed with exclamation mark (`!`) which will instead cause the tweak to be removed from selection, which is useful in cases when you want to apply a preset but omit a few specific tweaks. Alternatively, you can create a file where you write the function names (one function name per line, no commas or quotes, whitespaces allowed, comments starting with `#`) and then pass the filename using `-preset` parameter.  
Example of a preset file `mypreset.txt`:

    # Security tweaks
    EnableFirewall
    EnableDefender
    
    # UI tweaks
    ShowKnownExtensions
    ShowHiddenFiles   # Only hidden, not system

Command using the preset file above:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Core.ps1" -include "Functions.psm1" -include "Functions_Update.psm1" - include "Functions_Expansion.psm1" -preset "mypreset.txt"

Note that, although the example uses a `.txt` preset file, many text-based file formats are supported. The one used by default within the project is `.preset` to ease understanding.

As was previously stated, the script also supports inclusion of custom tweaks from user-supplied modules passed via `-include` parameter. The content of the user-supplied module is completely up to the user, however it is strongly recommended to have new tweaks separated from the main libraries in new file(s). The user-supplied scripts are loaded into the main script **Core.ps1** via `Import-Module`, so the library should ideally be a `.psm1` PowerShell module. 
Example of a user-supplied tweak library `mytweaks.psm1`:

```powershell
Function MyTweak1 {
    Write-Output "Running MyTweak1..."
    # Do something
}

Function MyTweak2 {
    Write-Output "Running MyTweak2..."
    # Do something else
}
```

Command using the script above:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Core.ps1" -include "mytweaks.psm1" MyTweak1 MyTweak2

### Combination

All features described above can be combined. You can have a preset which includes both tweaks from the original script and your personal ones. Both `-include` and `-preset` options can be used more than once, so you can split your tweaks into groups and then combine them based on your current needs. The `-include` modules are always imported before the first tweak is applied, so the order of the command line parameters doesn't matter and neither does the order of the tweaks (except for `RequireAdmin`, which should always be called first and `Restart`, which should be always called last). It can happen that some tweaks are applied more than once during a singe run because you have them in multiple presets. That shouldn't cause any problems as the tweaks are independent.  
Example of a preset file `otherpreset.txt`:

    MyTweak1
    MyTweak2
    !ShowHiddenFiles   # Will remove the tweak from selection
    WaitForKey

Command using all three examples combined:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Core.ps1" -include "Functions.psm1" -include "Functions_Update.psm1" - include "Functions_Expansion.psm1" -include "mytweaks.psm1" -preset "mypreset.txt" -preset "otherpreset.txt" Restart

### Logging

If you'd like to store output from the script execution, you can do so using `-log` parameter followed by a filename of the log file you want to create. For example:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Core.ps1" -include "Functions.psm1" -include "Functions_Update.psm1" - include "Functions_Expansion.psm1" -preset "mypreset.txt" -log "myoutput.log"

The logging is done using PowerShell `Start-Transcript` cmdlet, which writes extra information about current environment (date, machine and user name, command used for execution etc.) to the beginning of the file and logs both standard output and standard error streams.

Note that, although the example uses a `.log` file, many text-based file formats are supported. For example, the "Testing Functions" preset that is found inside the "Custom Presets" folder outputs a `.txt` log file.

### Filegen

Changing every preset after each new and/or updated function is a tedious task. To avoid doing so, an automatic file generation process has been developed within `filegen.ps1`. Said process uses the `filegen.preset` file as a template to build each and every preset, and it does so based on preset-based function bundles (which the process automatically uncomments).

New presets can be easily created from `filegen.ps1`. The file's code is commented so that it can be easily understood and specific functions have been developed to streamline the preset generation process, so the only real hassle is creating the selection of functions to uncomment.  
The following snippet showcases a preset construction example:

    $example_selection = @(
      'Function_1'
      'Function_2'
      'Function_3'
    )

    Generator -preset 'Example Name' -selection $example_selection -folder $W11_folder_custom

<br>

## Maintaining own forks

The easiest way to customize the script settings it is to create your own preset and, if needed, your own tweak scripts as described above. For an easy start, you can build upon any of the provided premade presets and maintain just that. If you choose to fork the script anyway, you don't need to comment or remove the actual functions in neither function library (the `.psm1` files) because if they are not called, they are not used.

If you wish to make more elaborate modifications of the basic script and incorporate some personal tweaks or adjustments, then I suggest doing it in a following way:

1. Fork the repository on GitHub (obviously).

2. Clone your fork on your computer.
   
   ```
   git clone https://github.com/<yournamehere>/Windows-Optimizer
   cd Windows-Optimizer
   ```

3. Add the original repository as a remote (*upstream*).
   
   ```
   git remote add upstream https://github.com/outerelocarlos/Windows-Optimizer
   ```

4. Commit your modifications as you see fit.

5. Once there are new additions in the upstream, create a temporary branch, fetch the changes and reset the branch to be identical with this repository.
   
   ```
   git branch upstream
   git checkout upstream
   git fetch upstream
   git reset --hard upstream/master
   ```

6. When you have the upstream branch up to date, check back your master and rebase it based on the upstream branch. If there are some conflicts between the changesets, you'll be asked to resolve them manually.
   
   ```
   git checkout master
   git rebase upstream
   ```

7. Eventually, delete the upstream branch and force push your changes back onto GitHub.
   
   ```
   git branch -D upstream
   git push -f master
   ```

**Word of warning:** Rebasing and force-pushing will change the history of your commits. The upside is that your adjustments will always stay on top of the commit history. The downside is that everybody remote-tracking your repository will always have to rebase and force-push too, otherwise their commit history will not match yours.

### Copyright licenses

As previously stated, Disassembler's work [is licensed under MIT](./MIT-LICENSE.md) whereas any and all changes performed upon his/her work [are licensed under GPL3](./GPL3-LICENSE.md). His functions and contributions have been meticulously isolated in the `Core.ps1` and `Functions.psm1` files, everything else cannot be close-sourced as per [GPL3 license restrictions](./GPL3-LICENSE.md).  
If you modify and/or fork this project you must include copyright notice as per both licenses' requirements, and should also include a link to this GitHub repository since it is likely that something will be changed, added or improved to keep track with future versions of Windows 10 and Windows 11.

<br>

## Contribution guidelines

Following is a list of rules which Disassembler was trying to apply in this project and to which I adhere if possible.  
The rules are not binding and I accept pull requests even if they don't adhere to them, as long as their purpose and content are clear. In cases when there are too many rule violations, I might simply redo the whole functionality and reject the PR while still crediting you. If you'd like to make my work easier, please consider adhering to the following rules too.

### Function naming

Try to give a function a meaningful name up to 25 characters long, which gives away the purpose of the function. Use verbs like `Enable`/`Disable`, `Show`/`Hide`, `Install`/`Uninstall`, `Add`/`Remove` in the beginning of the function name. In case the function doesn't fit any of these verbs, come up with another name, beginning with the verb `Set`, which indicates what the function does, e.g. `SetCurrentNetworkPrivate` and `SetCurrentNetworkPublic`.

### Revert functions

Always add a function with opposite name (or equivalent) which reverts the behavior to default. The default is considered freshly installed Windows 10, Windows 11 or Windows Server 2016 / 2019 with no adjustments made during or after the installation. If you don't have access to either of these, create the revert function to the best of your knowledge and I will fill in the rest if necessary.

### Function similarities

Check if there isn't already a function with similar purpose as the one you're trying to add. As long as the name and objective of the existing function is unchanged, feel free to add your tweak to that function rather than creating a new one.

### Function grouping

Try to group functions thematically. There are already several major groups (privacy, security, services etc.), but even within these, some tweaks may be related to each other. In such case, add a new tweak below the existing one and not to the end of the whole group.

### Repeatability

Unless applied on unsupported system, all functions have to be applicable repeatedly without any errors. When you're creating a registry key, always check first if the key doesn't happen to already exist. When you're deleting registry value, always append `-ErrorAction SilentlyContinue` to prevent errors while deleting already deleted values.

### Input / output hiding

Suppress all output generated by commands and cmdlets using `| Out-Null` or `-ErrorAction SilentlyContinue` where applicable. Whenever an input is needed, use appropriate arguments to suppress the prompt and programmatically provide values for the command to run (e.g. using `-Confirm:$false`). The only acceptable output is from the `Write-Output` cmdlets in the beginning of each function and from non-suppressible cmdlets like `Remove-AppxPackage`.

### Registry

Create the registry keys only if they don't exist on fresh installation if Windows 10, Windows 11 or Windows Server 2016 / 2019. When deleting registry, delete only registry values, not the whole keys. When you're setting registry values, always use `Set-ItemProperty` instead of `New-ItemProperty`. When you're removing registry values, choose either `Set-ItemProperty` or `Remove-ItemProperty` to reinstate the same situation as it was on the clean installation. Again, if you don't know what the original state was, let me know in PR description and I will fill in the gaps. When you need to use `HKEY_USERS` registry hive, always add following snippet before the registry modification to ensure portability.

```powershell
If (!(Test-Path "HKU:")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
```

### Force usage

Star Wars jokes aside, don't use `-Force` option unless absolutely necessary. The only permitted case is when you're creating a new registry key (not a value) and you need to ensure that all parent keys will be created as well. In such case always check first if the key doesn't already exist, otherwise you will delete all its existing values.

### Comments

Always add a simple comment above the function briefly describing what the function does, especially if it has an ambiguous name or if there is some logic hidden under the hood. If you know that the tweak doesn't work on some editions of Windows 10 or on Windows Server, state it in the comment too. Add a `Write-Output` cmdlet with the short description of action also to the first line of the function body, so the user can see what is being executed and which function is the problematic one whenever an error occurs. The comment is written in present simple tense, the `Write-Output` in present continuous with ellipsis (resp. three dots) at the end.

### Coding style

Indent using tabs, enclose all string values in double quotes (`"`) and strictly use `PascalCase` wherever possible. Put opening curly bracket on the same line as the function name or condition, but leave the closing bracket on a separate line for readability.

### Examples

**Naming example**: Consider function `EnableFastMenu`. What does it do? Which menu? How fast is *fast*? A better name might be `EnableFastMenuFlyout`, so it's a bit clearer that we're talking about the menu flyouts delays. But the counterpart function would be `DisableFastMenuFlyouts` which is not entirely true. We're not *disabling* anything, we're just making it slow again. So even better might be to name them `SetFastMenuFlyouts` and `SetSlowMenuFlyouts`. Or better yet, just add the functionality to already existing `SetVisualFXPerformance`/`SetVisualFXAppearance`. Even though the names are not 100% match, they aim to tweak similar aspects and operate within the same registry keys.

**Coding example:** The following code applies most of the rules mentioned above (naming, output hiding, repeatability, force usage, comments and coding style).

```powershell
# Enable some feature
Function EnableSomeFeature {
    Write-Output "Enabling some feature..."
    If (!(Test-Path "HKLM:\Some\Registry\Key")) {
        New-Item -Path "HKLM:\Some\Registry\Key" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Some\Registry\Key" -Name "SomeValueName" -Type String -Value "SomeValue"
}

# Disable some feature
Function DisableSomeFeature {
    Write-Output "Disabling some feature..."
    Remove-ItemProperty -Path "HKLM:\Some\Registry\Key" -Name "SomeValueName" -ErrorAction SilentlyContinue
}
```

<br>

## Documentation

This documentation aims to describe the functions' behavior.

### Setup

* `RequireAdmin`:  if the script is run without elevated privileges, this function relaunches it as an administrator.  
Due to the nature of authentication and privilege escalation mechanisms in Windows, only users belonging to *Administrators* group can successfully apply most tweaks. Standard users will get an UAC prompt asking for admin credentials which then causes the tweaks to be applied to the given admin account instead of the original non-privileged one. This can be circumvented by uncommenting this function, but most tweaks will output an error.

* `CreateRestorePoint`: Creates a restore point before running the script so that users can easily revert back to a point before the system was  modified.

### O&O ShutUp10 Setup

* `ShutUpStandard` / `ShutUpHardcore` / `ShutUpCustom`: The script makes use of the [O&O ShutUp10](https://www.oo-software.com/shutup10) tool to build a basis that is then reinforced and completed with the many tweaks that follow. Three different configuration files have been developed, and these are the functions that call upon them.

* `ShutUpStandard_Reverse` / `ShutUpHardcore_Reverse` / `ShutUpCustom_Reverse`: undo the changes done by the previous functions.

### Privacy Tweaks

* `DisableTelemetry` / `EnableTelemetry`: Microsoft's telemetry sends user data and activity back to Microsoft.  
Note: This tweak also disables the possibility to join Windows Insider Program and breaks Microsoft Intune enrollment/deployment, as these features require Telemetry data.  
Windows Update control panel may show the following message: "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going". In such case, enable telemetry, run Windows update and then disable telemetry again.
See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57 and https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/92

* `DisableThirdPartyTelemetry` / `EnableThirdPartyTelemetry`: Disables or enables telemetry from selected third party applications. It currently supports Google Chrome, Mozilla Firefox, CCleaner, Microsoft Office 2013 and Microsoft Office 2016.

* `DisableCortana` / `EnableCortana`: Cortana is Microsoft's own virtual assistant. I don't really recommend it (does not work that great), and Microsoft seems to less invested into it as of late.

* `DisableWiFiSense` / `EnableWiFiSense`: This feature automatically connects a system to open Wi-Fi hotspots when in range, which is more of a risk than an utility.

* `DisableSmartScreen` / `EnableSmartScreen`: SmartScreen is Windows' protection layer, which warns the user before running unsigned software.

* `DisableWebSearch` / `EnableWebSearch`: Disables or enables web search from within the Start Menu.

* `DisableAppSuggestions` / `EnableAppSuggestions`: Disables or enables Windows' app suggestions.

* `DisableActivityHistory` / `EnableActivityHistory`: Disables or enables the activity history feed from within Windows' task view.

* `DisableSensors` / `EnableSensors`: Disables or enables sensor features such as screen auto-rotation (might be useful for some laptops and for selected monitors).

* `DisableLocation` / `EnableLocation`: Disables or enables location features and functionalities.

* `DisableFindMyDevice` / `EnableFindMyDevice`: Disables or enables the "Find my device" functionality.

* `DisableMapUpdates` / `EnableMapUpdates`: Disables or enables map updates.

* `DisableFeedback` / `EnableFeedback`: The Feedback Hub app lets you tell Microsoft about any problems you run into while using Windows.

* `DisableTailoredExperiences` / `EnableTailoredExperiences`: Sends Microsoft user data to personalize tips, ads and recommendations.

* `DisableAdvertisingID` / `EnableAdvertisingID`: Retrieves a unique ID (hence sends Microsoft user data) to provide more relevant advertising.  
  This ID is per-user, per-device; all apps for a single user on a device have the same advertising ID.

* `DisableWebLangList` / `EnableWebLangList`: Websites can provide locally relevant content by accessing the system language list, and this tweaks allows or blocks said behavior.

* `DisableBiometrics` / `EnableBiometrics`: Disables or enables biometric features (such as fingerprint sensors or Windows Hello).

* `DisableCamera` / `EnableCamera`: Disables or enables the use of cameras (webcams, capture cards, etcetera).

* `DisableMicrophone` / `EnableMicrophone`: Disables or enables the use of microphones or any sound input devices.

* `DisableErrorReporting` / `EnableErrorReporting`: Sends Microsoft data to fix faults, crashes and other problems.

* `SetP2PUpdateDisable` / `SetP2PUpdateLocal` / `SetP2PUpdateInternet`: Controls the peer-to-peer (P2P) behavior of Windows Update (note: disabling this setting does not work as intended and thus it is not recommended).  
  This allows or blocks the ability of a system to upload an already downloaded Windows update to other systems on the net (either local or global, depending on the tweak).

* `DisableAutoLogger` / `EnableAutoLogger`: Seems to be part of DiagTrack and, as such, another telemetry component. Keyloggers record your keypresses, so theoretically this component could/would be sending them to Microsoft. I guess the idea is to improve their text prediction algorithms, but doing so without user consent feels oh-so-wrong.

* `DisableDiagTrack` / `EnableDiagTrack`: Another Microsoft's telemetry component, which sends data to Microsoft' servers periodically.

* `DisableWAPPush` / `EnableWAPPush`: Disables or enables WAP Push messages and notifications in Windows. Only really useful for those devices with mobile (3G/4G) connectivity.

* `DisableClearRecentFiles` / `EnableClearRecentFiles`: If enabled, this setting empties the most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications during every logout.

* `DisableRecentFiles` / `EnableRecentFiles`: If disabled, this setting stops the creation of most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.

### UWP Privacy Tweaks

* `DisableUWPBackgroundApps` / `EnableUWPBackgroundApps`: Disables or enables background activity for UWP applications.

* `DisableUWPVoiceActivation` / `EnableUWPVoiceActivation`: Disables or enables voice activation for UWP applications.

* `DisableUWPNotifications` / `EnableUWPNotifications`: Disables or enables notifications for UWP applications.

* `DisableUWPAccountInfo` / `EnableUWPAccountInfo`: Disables or enables access to account information (Microsoft's) for UWP applications.

* `DisableUWPContacts` / `EnableUWPContacts`: Disables or enables access to contacts for UWP applications.

* `DisableUWPCalendar` / `EnableUWPCalendar`: Disables or enables access to the calendar for UWP applications.

* `DisableUWPPhoneCalls` / `EnableUWPPhoneCalls`: Disables or enables access to phone calls for UWP applications.

* `DisableUWPCallHistory` / `EnableUWPCallHistory`: Disables or enables access to the phone call history for UWP applications.

* `DisableUWPEmail` / `EnableUWPEmail`: Disables or enables access to email for UWP applications.

* `DisableUWPTasks` / `EnableUWPTasks`: Disables or enables access to tasks for UWP applications.

* `DisableUWPMessaging` / `EnableUWPMessaging`: Disables or enables access to messaging (SMS, MMS) for UWP applications.

* `DisableUWPRadios` / `EnableUWPRadios`: Disables or enables access to radios (e.g. Bluetooth) for UWP applications.

* `DisableUWPOtherDevices` / `EnableUWPOtherDevices`: Disables or enables access to other devices (unpaired, beacons, TVs etc.) for UWP applications.

* `DisableUWPDiagInfo` / `EnableUWPDiagInfo`: Disables or enables access to diagnostic information for UWP applications.

* `DisableUWPFileSystem` / `EnableUWPFileSystem`: Disables or enables access to the system libraries for UWP applications.

* `DisableUWPSwapFile` / `EnableUWPSwapFile`: Disables or enables the creation and use of a _swapfile.sys_ file, which is used by UWP applications to store memory settings outside of the system RAM reducing the applications' fingerprint within this type of memory. Without a swap file, some modern Windows apps simply won't run — others might run for a while before crashing.

### Security Tweaks

* `SetUACLow` / `SetUACHigh`: Defines the amount of prompts by the User Account Control. It gets annoying but theoretically protects the user, so I would set it to low unless the system is for an user who knows nothing about PCs.

* `DisableSharingMappedDrives` / `EnableSharingMappedDrives`: Disables or enables the option to share drives over the network.

* `DisableAdminShares` / `EnableAdminShares`: Disables or enables implicit administrative shares.

* `DisableFirewall` / `EnableFirewall`: Disables or enables the Windows firewall.

* `HideDefenderTrayIcon` / `ShowDefenderTrayIcon`: Hides or shows the Windows Defender icon in the system tray.

* `DisableDefender` / `EnableDefender`: Disables or enables Windows Defender (Windows built-in anti-virus system).

* `DisableDefenderCloud` / `EnableDefenderCloud`: Disables or enables Windows Defender cloud functionalities (looks for files/threats in a Microsoft-hosted database to evaluate their danger).

* `DisableCtrldFolderAccess` / `EnableCtrldFolderAccess`: Controlled folder access is designed primarily to prevent ransomware from encrypting and taking your data hostage, but it also protects files from unwanted changes from other malicious programs. Despite being a valuable protection layer, it is undoubtedly over-protective: enabling it makes you unable to save files onto your computer via Word, Notepad... Only do so if privacy and security are significantly prioritized over usability.

* `DisableCIMemoryIntegrity` / `EnableCIMemoryIntegrity`: Memory integrity is a feature, part of core isolation, which helps prevent attempts to inject and run malware in high-security processes by making kernel memory pages executable only when they pass integrity check. These functions disable/enable said functionality.

* `DisableDefenderAppGuard` / `EnableDefenderAppGuard`: Windows Defender Application Guard runs the Microsoft Edge browser in an isolated, virtualized container. These functions disable/enable said functionality.

* `HideAccountProtectionWarn` / `ShowAccountProtectionWarn`: Hides or shows the "Account protection" area within Windows Defender. Doing so means that it will no longer appear on the home page of the Defender Security Center, and its icon will not be shown on the navigation bar on the side of the software.

* `DisableDownloadBlocking` / `EnableDownloadBlocking`: Windows sometimes blocks some downloads to protect users from malicious files. These functions disable/enable said functionality.

* `DisableScriptHost` / `EnableScriptHost`: Disables or enables the Windows Script Host, which allows for the execution of .vbs scripts and alike.

* `DisableDotNetStrongCrypto` / `EnableDotNetStrongCrypto`: Disables or enables strong cryptography for all .net applications.

* `DisableMeltdownCompatFlag` / `EnableMeltdownCompatFlag`: A flag to disable or enable the Meltdown/Spectre security patch. Older systems (particularly those with Intel CPUs) took a performance hit after the patch, so I have seen users disabling it to gain back that performance. However, doing so exposes the system to the aforementioned vulnerabilities.  
I have not tested these functions myself, so they might be deprecated.

* `DisableF8BootMenu` / `EnableF8BootMenu`: Disables and enables [the F8 advanced boot menu](https://i.imgur.com/DwIFS4b.jpeg).

* `DisableBootRecovery` / `EnableBootRecovery`: If your computer crashes or fails to boot twice, it will run Automatic Repair (sometimes fixing the issue at hand). These functions disable/enable said functionality.

* `DisableRecoveryAndReset` / `EnableRecoveryAndReset`: Disables and enables the recovery and reset feature (which is based on system restore points). It is extremely helpful at times, so leaving it enabled is recommended. These functions disable/enable said functionality.

* `SetDEPOptOut` / `SetDEPOptIn`: Data Execution Prevention (DEP) prevents code from running in memory that is not authorized.

### Network Tweaks

* `SetCurrentNetworkPrivate` / `SetCurrentNetworkPublic`: Sets current network to either "Private" or "Public".

* `SetUnknownNetworksPrivate` / `SetUnknownNetworksPublic`: Sets unknown networks to either "Private" or "Public".

* `DisableNetDevicesAutoInst` / `EnableNetDevicesAutoInst`: Disables or enables the automatic installation of network devices.

* `DisableHomeGroups` / `EnableHomeGroups`: Disables or enables the HomeGroup feature. Note that since Windows 10 Version 1803 the feature has been disconnected.

* `DisableSMB1` / `EnableSMB1`: SMB (Server Message Block) is a client-server communication protocol. Despite its usefulness, SMB Version 1 (SMB1) is an old and insecure networking protocol, so Windows 10 no longer installs it by default. These functions Installs and enables (or uninstalls and disables) said protocol.  
Note that both functions make use of the "Set-SmbServerConfiguration" command, which might not exist in the system if the "SMB Server" feature is not enabled.

* `DisableSMBServer` / `EnableSMBServer`: Disables or enables the SMB server side of the protocol.

* `DisableNetBIOS` / `EnableNetBIOS`: NetBIOS Frames (NBF) allow applications and computers on a local area network (LAN) to communicate with network hardware and to transmit data across the network. These functions disable/enable said functionality.

* `DisableLLMNR` / `EnableLLMNR`: The Link-Local Multicast Name Resolution is a protocol based on the Domain Name System packet format that allows both IPv4 and IPv6 hosts to perform name resolution for hosts on the same local link. These functions disable/enable said functionality.

* `DisableLLDP` / `EnableLLDP`: Disables or enables Local-Link Discovery Protocol (LLDP) for all installed network interfaces.

* `DisableLLTD` / `EnableLLTD`: Disable or enables Local-Link Topology Discovery (LLTD) for all installed network interfaces.

* `DisableMSNetClient` / `EnableMSNetClient`: Disables or enables the Client for Microsoft Networks for all installed network interfaces.

* `DisableQoS` / `EnableQoS`: Disables or enables Quality of Service (QoS) packet scheduler for all installed network interfaces.

* `DisableIPv4` / `EnableIPv4`: Disables or enables IPv4 stack for all installed network interfaces.

* `DisableIPv6` / `EnableIPv6`: Disables or enables IPv6 stack for all installed network interfaces.

* `DisableNCSIProbe` / `EnableNCSIProbe`: Disables or enables Network Connectivity Status Indicator (NCSI) active test. This may reduce the ability of OS and other components to determine internet access, however protects against a specific type of zero-click attack. See https://github.com/Disassembler0/Win10-Initial-Setup-Script/pull/111 for details.

* `DisableConnectionSharing` / `EnableConnectionSharing`: Disables or enables Internet Connection Sharing (e.g. mobile hotspot).

* `DisableRemoteAssistance` / `EnableRemoteAssistance`: Disables or enables the Remote Assistance feature.

* `DisableRemoteDesktop` / `EnableRemoteDesktop`: Disables or enables the Remote Desktop feature.

* `DisableRemoteDesktopNLA` / `EnableRemoteDesktopNLA`: Disables or enables Network Level Authentication (NLA) for Remote Desktop.

* `DisableNetworkDiscovery` / `EnableNetworkDiscovery`: Disables or enables Network Discovery, allowing the PC to find and interact with other computers and devices on the network (and vice-versa).

* `DisableFileAndPrinterSharing` / `EnableFileAndPrinterSharing`: Disables or enables file and printer sharing over the network.

* `IncreaseIRPStackSize` / `DefaultIRPStackSize`: Increases the IRP stack size for a faster network within Windows (or sets it back to default).

### Service Tweaks

* `DisableUpdateMSRT` / `EnableUpdateMSRT`: Disables or enables the Windows malicious software removal tool.

* `DisableUpdateDriver` / `EnableUpdateDriver`: Disables or enables Windows Update ability to automatically update drivers.

* `DisableUpdateMSProducts` / `EnableUpdateMSProducts`: Disables or enables Windows Update ability to automatically update Microsoft software.

* `DisableUpdateAutoDownload` / `EnableUpdateAutoDownload`: Disables or enables Windows Update ability to automatically download updates.

* `DisableUpdateRestart` / `EnableUpdateRestart`: Disables or enables the automatic restart after an update.

* `DisableDelayedFeatureUpdates` / `EnableDelayedFeatureUpdates`: Delays (or not) feature updates (useful if stability is prioritized).

* `DisableW11_TPMRequirement` / `EnableW11_TPMRequirement`: Disables or enables the TPM hardware requirement so that unsupported systems can update to Windows 11.

* `DisableMaintenanceWakeUp` / `EnableMaintenanceWakeUp`: Disables or enables the system ability to wake up out of active hours for maintenance tasks (updating system components, etc.). 

* `DisableLogin` / `EnableLogin`: Disables or enables the signing on process when booting up the system. Note that this function prompts the user for its password, without which it cannot bypass the login process.

* `DisableAutoRestartLogin` / `EnableAutoRestartLogin`: Disables or enables the signing on process when the system is automatically restarted (e.g.: when installing a program).

* `DisableSharedExperiences` / `EnableSharedExperiences`: Disables or enables the "Shared Experiences" feature, which allows a system to share web links, messages, app data, etc., with other Windows PCs or linked Android phones.

* `DisableClipboardHistory` / `EnableClipboardHistory`: Disables or enables the clipboard history (Windows + V).

* `DisableAutoplay` / `EnableAutoplay`: Disables or enables the autoplay functionality which automatically plays CDs, DVDs or other drives when plugged into the system.

* `DisableAutorun` / `EnableAutorun`: Disables or enables the autorun functionality which automatically plays CDs, DVDs or other drives when plugged into the system.

* `DisableRestorePoints` / `EnableRestorePoints`: Disables or enables system restore points, which can actually help when issues arise by going back to a time when they weren't present.

* `DisableStorageSense` / `EnableStorageSense`: Storage Sense can automatically delete unnecessary files to maintain a healthy level of free disk space. These functions disable/enable said functionality.

* `DisableDefragmentation` / `EnableDefragmentation`: Defragmentation optimizes drives to avoid them wasting over time (particularly useful with SSDs). These functions disable/enable said functionality.

* `DisableSuperfetch` / `EnableSuperfetch`: Theoretically, superfetch caches data into the RAM so that it can be immediately available to your application. However, there does not exist any perceptible performance increase (in fact, some users state that disabling superfetch solves system slowdowns). Note that memory compression depends on superfetch to work, although most people neither use said feature nor know of its existence and behavior. These functions disable/enable said functionality, and I recommend leaving it disabled. 

* `DisableIndexing` / `EnableIndexing`: Disables or enables file indexing, which can be too demanding of old HDD drives (leading to 100% usage).

* `DisableRecycleBin` / `EnableRecycleBin`: Disables or enables the recycle bin. If disabled, files are unrecoverable.

* `DisableNTFSLongPaths` / `EnableNTFSLongPaths`: Enabling this will remove the NTFS length limit of 260 symbols for the file name. Disabling it brings back that limitation.

* `DisableNTFSLastAccess` / `EnableNTFSLastAccess`: Windows updates each and all files with the “last access update time”. Depending on the system and scenario, that might take a toll on the system resources. These functions disable/enable said functionality.

* `SetBIOSTimeLocal` / `SetBIOSTimeUTC`: Defines the BIOS time format. UTC ensures consistency with Linux-based dual boots.

* `SetTimeZoneUTC` / `SetTimeZoneCEST`: Defines the system's timezone, hence the time displayed in the system clock.

* `DisableHibernation` / `EnableHibernation`: Disables or enables the hibernation feature, which was designed for laptops to save power in a deeper state than "Sleep".

* `DisableSleepButton` / `EnableSleepButton`: Disables or enables the sleep option within the power menu.

* `DisableSleepTimeout` / `EnableSleepTimeout`: Disables or enables the sleep timeout after which the system goes to sleep.

* `DisableFastStartup` / `EnableFastStartup`: With fast startup enabled, choosing to shut down your PC might look like you’re completely shutting things down, but in reality, your PC is entering a mix between a shutdown and hibernation. A hibernation file is indeed used, although it is smaller than usual. Why? You’re logged off before the file is created, meaning your session is not recorded. The speed boost comes from the Windows kernel being saved on your hard drive and loaded when booting.  
  This intermediate state might lead to some misbehaviors and issues, so unless the system is HDD-based I recommend disabling this feature.

* `DisableAutoRebootOnCrash` / `EnableAutoRebootOnCrash`: Disables or enables the automatic reboot after a system crash.

* `DisableHAGS` / `EnableHAGS`: Hardware-accelerated GPU Scheduling (HAGS) is a great thing on paper, offloading some CPU tasks onto the more powerful GPU. This also gives the GPU more control over said tasks, although not every software works well with HAGS enabled. These functions disable/enable said functionality.

* `OptimizeServiceHost` / `DefaultServiceHost`: Group svhost.exe processes together to reduce their memory consumption.

* `RestoreMissingPowerPlans`: Sometimes, Windows does not load its power plans. Sometimes, they are lost with an update. This function brings them back (don't use this if you have not lost your power plans, you would end up having duplicates).

### UI Tweaks

* `DisableActionCenter` / `EnableActionCenter`: Disables or enables the Windows Action Center (Windows + A).

* `DisableLockScreen` / `EnableLockScreen`: Disables or enables the lockscreen (disabling it speeds up starting time ever so slightly).

* `DisableLockScreenRS1` / `EnableLockScreenRS1`: Disables or enables the Windows+L shortcut lockscreen.

* `HideNetworkFromLockScreen` / `ShowNetworkOnLockScreen`: Hides or shows the current network in the lockscreen.

* `HideShutdownOnLockScreen` / `ShowShutdownOnLockScreen`: Hides or shows the power button/interface in the lockscreen.

* `DisableLockScreenBlur` / `EnableLockScreenBlur`: Disables or enables the lockscreen blur.

* `DisableAeroShake` / `EnableAeroShake`: Aero shake minimizes everything when shaking a moving windows. These functions disable/enable said functionality.

* `DisableAccessibilityKeys` / `EnableAccessibilityKeys`: Some Windows shortcuts are aimed towards accessibility features. However, they are often triggered by accident so disabling them is recommended if said accessibility features are not needed.

* `HideTaskManagerDetails` / `ShowTaskManagerDetails`: Hides or shows detailed information within the task manager.

* `HideFileOperationsDetails` / `ShowFileOperationsDetails`: Hides or shows detailed information when moving files around.

* `DisableFileDeleteConfirm` / `EnableFileDeleteConfirm`: Disables or enables the confirmation prompt when deleting a file.

* `HideTaskbarSearch` / `ShowTaskbarSearchIcon` / `ShowTaskbarSearchBox`: Determines how to display the search feature within the taskbar: not at all, as an icon and as a search box (respectively).

* `HideTaskView` / `ShowTaskView`: Hides or shows the task view button in the taskbar.

* `ShowSmallTaskbarIcons` / `ShowLargeTaskbarIcons`: Defines the size of the taskbar icons.

* `SetTaskbarCombineAlways` / `SetTaskbarCombineWhenFull` / `SetTaskbarCombineNever`: Determines how to display the taskbar items/tabs.

* `HideNewsAndInterests` / `ShowNewsAndInterestsIcon` / `ShowNewsAndInterestsTextbox`: Determines how to display the "News and Interests" feature.

* `DisableNewsAndInterests` / `EnableNewsAndInterests`: Disables or enables the "News and Interests" feature.

* `HideMeetNowFromTaskbar` / `ShowMeetNowInTaskbar`: Hides or shows the "Meet Now" icon from the taskbar.

* `HideTaskbarPeopleIcon` / `ShowTaskbarPeopleIcon`: Hides or shows the "People" icon from the taskbar.

* `HideTrayIcons` / `ShowTrayIcons`: Hides or shows system tray icons.

* `HideSecondsFromTaskbar` / `ShowSecondsInTaskbar`: Hides or shows the seconds from the taskbar time.

* `DisableSearchAppInStore` / `EnableSearchAppInStore`: Windows Search might search your input in the Windows Store. These functions disable/enable said functionality.

* `DisableNewAppPrompt` / `EnableNewAppPrompt`: Windows warns if you have a new app that can open a given type of file. 

* `HideRecentlyAddedApps` / `ShowRecentlyAddedApps`: Hides or shows recently added apps in the Start Menu.

* `HideMostUsedApps` / `ShowMostUsedApps`: Hides or shows the most used apps in the Start Menu.

* `SetWinXMenuPowerShell` / `SetWinXMenuCmd`: Determines whether to use PowerShell or cmd.exe through the Windows+X menu.

* `SetControlPanelSmallIcons` / `SetControlPanelLargeIcons` / `SetControlPanelCategories`: Determines the Control Panel layout.

* `DisableShortcutInName` / `EnableShortcutInName`: Disables or enables the "Shortcut" being overly explicit in the shortcuts' files.

* `HideShortcutArrow` / `ShowShortcutArrow`: Hides or shows the shortcut arrow in shortcuts.

* `SetVisualFXAppearance` / `SetVisualFXPerformance`: The performance mode disables most system animations (note that there is not much performance to gain though).

* `DisableTitleBarColor` / `EnableTitleBarColor`: Disable or enables the window title bar color.

* `SetAppsDarkMode` / `SetAppsLightMode`: Sets dark/light mode in applications.

* `SetSystemDarkMode` / `SetSystemLightMode`: Sets dark/light mode system-wide.

* `RemoveENKeyboard` / `AddENKeyboard`: Removes or adds an US-keyboard layout. These functions stopped working at some point, but I don't find them useful enough to warrant a fix (they are now deprecated).

* `DisableNumlock` / `EnableNumlock`: Disables or enables the numeric lock at system startup.

* `DisableEnhPointerPrecision` / `EnableEnhPointerPrecision`: Enhanced pointer precision actually worsens consistency by adding an acceleration component. I recommend disabling it.

* `SetSoundSchemeNone` / `SetSoundSchemeDefault`: Removes or restores the system sounds.

* `DisableStartupSound` / `EnableStartupSound`: Disables or enables the system startup sound.

* `DisableChangingSoundScheme` / `EnableChangingSoundScheme`: Disables or enables the option to change the system sound scheme.

* `DisableVerboseStatus` / `EnableVerboseStatus`: Disables or enables detailed status messages when starting up and shutting down the system, useful for troubleshooting.

* `DisableF1HelpKey` / `EnableF1HelpKey`: Disables or enables the F1 shortcut which calls for help (bringing out a guiding or troubleshooting manual).

### Explorer UI Tweaks

* `HideExplorerTitleFullPath` / `ShowExplorerTitleFullPath`: Hides or shows the full path in the title bar.

* `HideKnownExtensions` / `ShowKnownExtensions`: Hides or shows known extensions.

* `HideHiddenFiles` / `ShowHiddenFiles`: Hides or shows hidden files.

* `HideSuperHiddenFiles` / `ShowSuperHiddenFiles`: Hides or shows super hidden files.

* `HideEmptyDrives` / `ShowEmptyDrives`: Hides or shows empty drives in "This PC".

* `HideFolderMergeConflicts` / `ShowFolderMergeConflicts`: Hides or shows the prompt shown when copying a file/folder to a destination that already has a file/folder with that name. Hiding this prompt overwrites by default, which might lead to information loss. 

* `DisableDoForAllCopyPaste` / `EnableDoForAllCopyPaste`: Unchecks or checks (respectively) the "Do for all" checkbox when moving files.

* `DisableNavPaneExpand` / `EnableNavPaneExpand`: Disables or enables the navigation pane expanding to the current folder.

* `HideNavPaneAllFolders` / `ShowNavPaneAllFolders`: Hides or shows all folders from Explorer navigation pane except the basic ones (Quick access, OneDrive, This PC, Network), some of which can be disabled using other tweaks.

* `HideNavPaneLibraries` / `ShowNavPaneLibraries`: Hides or shows the system libraries from the navigation pane.

* `DisableFldrSeparateProcess` / `EnableFldrSeparateProcess`: Disabled by default, enabling it opens a new window when clicking upon a folder.

* `DisableRestoreFldrWindows` / `EnableRestoreFldrWindows`: Disables or enables restoring previous folder windows at logon.

* `HideEncCompFilesColor` / `ShowEncCompFilesColor`: Hides or shows encrypted or compressed NTFS files in color.

* `DisableSharingWizard` / `EnableSharingWizard`: Disables or enables the network sharing wizard.

* `HideSelectCheckboxes` / `ShowSelectCheckboxes`: Hides or shows the checkboxes that highlight whether or not a file has been selected. I find them redundant, but it's up to personal preference.

* `HideSyncNotifications` / `ShowSyncNotifications`: Hides or shows OneDrive and Office sync notifications.

* `HideRecentShortcuts` / `ShowRecentShortcuts`: Hides or shows recent files and folders from the Quick Access.

* `SetExplorerThisPC` / `SetExplorerQuickAccess`: Sets "This PC" or "Quick Access" (respectively) as the default destination when opening Windows Explorer.

* `HideQuickAccess` / `ShowQuickAccess`: Hides or shows the "Quick Access" shortcut from the navigation pane.

* `HideRecycleBinFromNavigationPane` / `ShowRecycleBinInNavigationPane`: Hides or shows the "Recycle Bin" shortcut from the navigation pane.

* `HideRecycleBinFromDesktop` / `ShowRecycleBinOnDesktop`: Hides or shows the "Recycle Bin" shortcut from the desktop.

* `HideThisPCFromDesktop` / `ShowThisPCOnDesktop`: Hides or shows the "This PC" shortcut from the desktop.

* `HideUserFolderFromDesktop` / `ShowUserFolderOnDesktop`: Hides or shows the user folder shortcut from the desktop.

* `HideControlPanelFromDesktop` / `ShowControlPanelOnDesktop`: Hides or shows the "Control Panel" shortcut from the desktop.

* `HideNetworkFromDesktop` / `ShowNetworkOnDesktop`: Hides or shows the "Network" shortcut from the desktop.

* `HideDesktopIcons` / `ShowDesktopIcons`: Hides or shows the desktop icons.

* `HideBuildNumberFromDesktop` / `ShowBuildNumberOnDesktop`: Hides or shows the system build number from the desktop.

* `HideDesktopFromThisPC` / `ShowDesktopInThisPC`: Hides or shows the "Desktop" shortcut from "This PC".

* `HideDesktopFromExplorer` / `ShowDesktopInExplorer`: Hides or shows the "Desktop" shortcut from the navigation pane.

* `HideDocumentsFromThisPC` / `ShowDocumentsInThisPC`: Hides or shows the "Documents" shortcut from "This PC".

* `HideDocumentsFromExplorer` / `ShowDocumentsInExplorer`: Hides or shows the "Documents" shortcut from the navigation pane.

* `HideDownloadsFromThisPC` / `ShowDownloadsInThisPC`: Hides or shows the "Downloads" shortcut from "This PC".

* `HideDownloadsFromExplorer` / `ShowDownloadsInExplorer`: Hides or shows the "Downloads" shortcut from the navigation pane.

* `HideMusicFromThisPC` / `ShowMusicInThisPC`: Hides or shows the "Music" shortcut from "This PC".

* `HideMusicFromExplorer` / `ShowMusicInExplorer`: Hides or shows the "Music" shortcut from the navigation pane.

* `HidePicturesFromThisPC` / `ShowPicturesInThisPC`: Hides or shows the "Pictures" shortcut from "This PC".

* `HidePicturesFromExplorer` / `ShowPicturesInExplorer`: Hides or shows the "Pictures" shortcut from the navigation pane.

* `HideVideosFromThisPC` / `ShowVideosInThisPC`: Hides or shows the "Videos" shortcut from "This PC".

* `HideVideosFromExplorer` / `ShowVideosInExplorer`: Hides or shows the "Videos" shortcut from the navigation pane.

* `Hide3DObjectsFromThisPC` / `Show3DObjectsInThisPC`: Hides or shows the "3D Objects" shortcut from "This PC".

* `Hide3DObjectsFromExplorer` / `Show3DObjectsInExplorer`: Hides or shows the "3D Objects" shortcut from the navigation pane.

* `HideNetworkFromExplorer` / `ShowNetworkInExplorer`: Hides or shows the "Network" shortcut from the navigation pane.

* `HideIncludeInLibraryMenu` / `ShowIncludeInLibraryMenu`: Hides or shows the "Include in library" item from the context menu.

* `HideGiveAccessToMenu` / `ShowGiveAccessToMenu`: Hides or shows the "Give access to" item from the context menu.

* `HideShareMenu` / `ShowShareMenu`: Hides or shows the "Share" item from the context menu.

* `DisableThumbnails` / `EnableThumbnails`: Disables or enables thumbnails (if disabled, file extension icons are shown).

* `DisableThumbnailCache` / `EnableThumbnailCache`: Disables or enables the creation of thumbnail cache files.

* `DisableThumbsDBOnNetwork` / `EnableThumbsDBOnNetwork`: Disables or enables the creation of Thumbs.db thumbnail cache files on network folders.

* `MenuShowDelay_Default` / `MenuShowDelay_200`: / `MenuShowDelay_100` / `MenuShowDelay_50` / `MenuShowDelay_20` : Hovering over a dropdown menu displays its items, which takes a while to appear. These functions define the duration of said delay in milliseconds (with the default value being 400ms).

### Windows 11 UI Tweaks

* `SetStartMenuLeft` / `SetStartMenuCenter`: Determines the location of the Windows Start Menu.

* `SetClassicContextMenu` / `SetModernContextMenu`: Determines whether to use the new context menu or the classic one.

* `DisableExplorerCompactView` / `EnableExplorerCompactView`: Disables or enables the Windows Explorer compact view (the classic one).

* `DisableExplorerRibbonBar` / `EnableExplorerRibbonBar`: Disables or enables the Windows Explorer top ribbon bar (from Windows 10).

* `HideChatFromTaskbar` / `ShowChatInTaskbar`: Hides or shows the "Chat" icon from the taskbar.

* `HideWidgetsFromTaskbar` / `ShowWidgetsInTaskbar`: Hides or shows the "Widgets" icon from the taskbar.

### Application Tweaks

* `DisableOneDrive` / `EnableOneDrive`: These functions do not uninstall nor install OneDrive but disable/enable it instead (although disabled, OneDrive is still installed on the system).

* `UninstallOneDrive` / `InstallOneDrive`: Uninstalls or installs OneDrive.

* `DisableTeamsAutoStart` / `EnableTeamsAutoStart`: Disables or enables Microsoft Teams autostarting at user login.

* `UninstallTeams` / `InstallTeams`: Uninstalls or installs Microsoft Teams.

* `UninstallWorstMsftBloat` / `InstallWorstMsftBloat`: Uninstalls or installs the worst selection of Microsoft developed software.

* `UninstallBestMsftBloat` / `InstallBestMsftBloat`: Uninstalls or installs the better selection of Microsoft developed software.

* `UninstallCustomMsftBloat` / `InstallCustomMsftBloat`: Uninstalls or installs my custom selection of Microsoft developed software.

* `UninstallWorstThirdPartyBloat` / `InstallWorstThirdPartyBloat`: Uninstalls or installs the worst selection of third-party developed software.

* `UninstallBestThirdPartyBloat` / `InstallBestThirdPartyBloat`: Uninstalls or installs the better selection of third-party developed software.

* `UninstallCustomThirdPartyBloat` / `InstallCustomThirdPartyBloat`: Uninstalls or installs my custom selection of third-party developed software.

* `UninstallWindowsStore` / `InstallWindowsStore`: Uninstalls or installs the Windows Store.

* `DisableXboxFeatures` / `EnableXboxFeatures`: Disables or enables Xbox features from the system. 

* `DisableFullscreenOptims` / `EnableFullscreenOptims`: Disables or enables fullscreen optimizations. These basically turn fullscreen applications and games into borderless windowed ones. I rather have them disabled.

* `DisableAdobeFlash` / `EnableAdobeFlash`: Disables or enables the built-in Adobe Flash in Internet Explorer and Microsoft Edge. Flash was deprecated by the end of 2020 with no additional updates or security patches after the fact, so disabling and/or uninstalling the runtime is recommended.

* `DisableEdgePreload` / `EnableEdgePreload`: Disables or enables Microsoft Edge ability to preload tabs (speeds up navigation at the cost of privacy and system memory).

* `DisableEdgeShortcutCreation` / `EnableEdgeShortcutCreation`: Disables or enables Microsoft Edge desktop shortcut creation after certain Windows updates.

* `DisableIEFirstRun` / `EnableIEFirstRun`: Disables or enables Internet Explorer's first run wizard.

* `DisableFirstLogonAnimation` / `EnableFirstLogonAnimation`: Disables or enables the "Hi!" first logon animation, which is replaced by a "Preparing Windows" message.

* `DisableMediaSharing` / `EnableMediaSharing`: Disables or enables Windows Media Player media sharing feature.

* `DisableMediaOnlineAccess` / `EnableMediaOnlineAccess`: Disables or enables Windows Media Player online access, meaning audio file metadata download, radio presets, DRM...

* `DisableDeveloperMode` / `EnableDeveloperMode`: Windows "Developer mode" allows users to tweak and handle more advanced settings and features targeted towards developers. These functions disable or enable this mode.

* `UninstallMediaPlayer` / `InstallMediaPlayer`: Uninstalls or installs Windows Media Player.

* `UninstallInternetExplorer` / `InstallInternetExplorer`: Uninstalls or installs Internet Explorer.

* `UninstallWorkFolders` / `InstallWorkFolders`: Uninstalls or installs [Work Folders](https://docs.microsoft.com/windows-server/storage/work-folders/work-folders-overview), a WAN-based feature that enabled users to have some files (work files) accesible from more than one system (and synchronized at all times).

* `UninstallHelloFace` / `InstallHelloFace`: Uninstalls or installs the [Windows Hello face authentication](https://docs.microsoft.com/windows-hardware/design/device-experiences/windows-hello-face-authentication) (which uses facial recognition to unlock the system and/or some specific features such as Microsoft Passport).

* `UninstallMathRecognizer` / `InstallMathRecognizer`: Uninstalls or installs the Windows Math Recognizer and associated components (e.g. Math Input Panel).

* `UninstallPowerShellV2` / `InstallPowerShellV2`: Uninstalls or installs Powershell 2.0, which is deprecated since September 2018. However, uninstalling the component might affect Microsoft Diagnostic Tool and possibly other scripts.

* `UninstallPowerShellISE` / `InstallPowerShellISE`: Uninstalls or installs the Powershell IDE.

* `UninstallLinuxSubsystem` / `InstallLinuxSubsystem`: Uninstalls or installs the [Windows Subsystem for Linux](https://docs.microsoft.com/windows/wsl/about).

* `UninstallHyperV` / `InstallHyperV`: Uninstalls or installs the [HyperV virtualization software](https://docs.microsoft.com/virtualization/hyper-v-on-windows/).

* `UninstallSSHClient` / `InstallSSHClient`: Uninstalls or installs [the client-side of the SSH communication protocol](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse) (based on OpenSSH).

* `UninstallSSHServer` / `InstallSSHServer`: Uninstalls or installs [the server-side of the SSH communication protocol](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse) (based on OpenSSH).

* `UninstallTelnetClient` / `InstallTelnetClient`: Uninstalls or installs a [Telnet](https://docs.microsoft.com/windows-server/administration/windows-commands/telnet) client.

* `UninstallNET23` / `InstallNET23`: Uninstalls or installs .NET Framework 2.0, 3.0 and 3.5 runtimes.

* `UnsetPhotoViewerAssociation` / `SetPhotoViewerAssociation`: Unsets or sets Windows Photo Viewer as the default application for bmp, gif, jpg, png and tif files.

* `RemovePhotoViewerOpenWith` / `AddPhotoViewerOpenWith`: Removes or adds Windows Photo Viewer to the "Open with" dropdown in the context menu.

* `UninstallPDFPrinter` / `InstallPDFPrinter`: Uninstalls or installs a virtual PDF printer (which saves files as PDF when printing them).

* `UninstallXPSPrinter` / `InstallXPSPrinter`: Uninstalls or installs a virtual XPS printer (which saves files as XPS when printing them).

* `RemoveFaxPrinter` / `AddFaxPrinter`: Removes or adds a virtual fax printer.

* `UninstallFaxAndScan` / `InstallFaxAndScan`: Uninstalls or installs the [Windows Fax and Scan](https://en.wikipedia.org/wiki/Windows_Fax_and_Scan) services.

### Server Specific Tweaks

* `HideServerManagerOnLogin` / `ShowServerManagerOnLogin`:  Hides or shows the [Server Manager](https://docs.microsoft.com/windows-server/administration/server-manager/server-manager) management console after login.

* `DisableShutdownTracker` / `EnableShutdownTracker`: Disables or enable the [Shutdown Event Tracker](https://docs.microsoft.com/troubleshoot/windows-server/application-management/description-shutdown-event-tracker), which enables the user or application to document the reason for shutting down or restarting the system.

* `DisablePasswordPolicy` / `EnablePasswordPolicy`: Disables or enables the password complexity and maximum age requirements.

* `DisableCtrlAltDelLogin` / `EnableCtrlAltDelLogin`: Disables or enables the need to press Ctrl+Alt+Supr in the lockscreen to input user credentials.

* `DisableIEEnhancedSecurity` / `EnableIEEnhancedSecurity`: Disables or enables the [Internet Explorer Enhanced Security Configuration](https://docs.microsoft.com/troubleshoot/developer/browsers/security-privacy/enhanced-security-configuration-faq).

* `DisableAudio` / `EnableAudio`: Disables or enables audio on the server-side of a server-client connection (e.g. with Remote Desktop).

### Unpinning

* `UnpinStartMenuTiles`: Unpins all of the Start Menu tiles.

* `UnpinTaskbarIcons`: Unpins all of the taskbar icons.

### Finishing Functions

* `WaitForY`: Waits for user confirmation (Y keypress) to continue (onto the restart process).

* `Restart`: Restarts the system to properly apply the changes performed by this script.

### Current Issues

The following is a list of functions that are not working as intended. As such, they are omitted from all premade presets and tweaks so that users may not make use of them.

#### Deprecated Functions

* `RemoveENKeyboard` / `AddENKeyboard`: They stopped working at some point, but I don't find them useful enough to warrant a fix.

#### Windows Fault

* `EnableSMB1`: "Set-SmbServerConfiguration : The specified service does not exist". Yet it does, see `Get-SmbServerConfiguration | Format-List EnableSMB1Protocol`.

* The **Add-WindowsCapability** cmdlet command is not working as intended (`Add-WindowsCapability : Element not found`).  
The following functions are affected:

  * `DisableRemoteAssistance` / `EnableRemoteAssistance`
  
  * `UninstallMediaPlayer` / `InstallMediaPlayer`

  * `UninstallInternetExplorer` / `InstallInternetExplorer`

  * `UninstallHelloFace` / `InstallHelloFace`

  * `UninstallMathRecognizer` / `InstallMathRecognizer`

  * `UninstallPowerShellISE` / `InstallPowerShellISE`

  * `UninstallSSHClient` / `InstallSSHClient`

  * `UninstallSSHServer` / `InstallSSHServer`
  
  * `UninstallNET23` / `InstallNET23`

  * `UninstallFaxAndScan` / `InstallFaxAndScan`

* `HideNewsAndInterests` / `ShowNewsAndInterestsIcon` / `ShowNewsAndInterestsTextbox`: Windows resets the changes for some unknown reason. Use `DisableNewsAndInterests` or `EnableNewsAndInterests` instead.