### Instructions for macOS Users
The following steps should be executed in a Terminal application. Tip: press `Command (⌘) + Space` and search for `terminal`. 

#### 1. Xcode Command Line Tools

To install, run the following command from your terminal:

``` bash
xcode-select --install
```

Upon running the command, you should see a popup appear.
Click on `Install` to continue the installation process.

#### 2. Homebrew Package Manager

Homebrew is a package manager for macOS that allows one to install packages from the command line easily. You can use the package manager of your preference.

To install the Homebrew package manager, see: https://brew.sh

Note: If you run into issues while installing Homebrew or pulling packages, refer to [Homebrew's troubleshooting page](https://docs.brew.sh/Troubleshooting).

#### 3. Install Required Dependencies

On the Terminal, using Homebrew, run the following:
```bash
brew update
brew install gcc pkg-config openssl
```
* At this point you can proceed from cargo and rust at the previous section.
