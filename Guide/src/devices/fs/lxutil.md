## LxUtil

LxUtil is a library that emulates Linux file system semantics on Windows. It consists of two
components: a Windows DLL and a Rust crate.

### Windows DLL

The LxUtil library on Windows was developed as part of the Windows Subsystem for Linux, and contains
code that is shared between the DrvFs file system used to provide Windows file system access in
WSL 1, and the 9p file server used to do the same in WSL 2 (note: this is unrelated to the 9p
server used in OpenVMM).

Among other things, this library provides functionality to add Linux attributes (mode, owner user
and group ID) to NTFS files, providing support for operations such as `chown` and `chmod`. It also
handles special file types (symbolic links, device files, fifos, and sockets), and implements the
Linux semantics for operations such as `unlink`, `rename`, and `getdents`.

LxUtil takes care of abstracting away the differences between the underlying file systems,
supporting most Windows file systems such as NTFS, ReFS, FAT, and remote file systems like SMB.
Exactly what set of functionality is provided depends on the capabilities of the underlying file
system; for example, FAT does not support Linux attributes or special file types.

In addition, many of the functions of LxUtil can be controlled by options, so the user can
choose whether to e.g. use Linux attributes, or limit functionality to what's available on
Windows natively.

The source code for lxutil.dll is in the Windows OS repo, and the DLL is built from there.

### Rust crate

OpenVMM includes a Rust crate that wraps the LxUtil library and provides additional functionality.

The LxUtil crate wraps LxUtil functionality in an API that is more natural to use from Rust.
It also implements support for opening/creating files, which is not present in the Windows DLL
because it could not be shared between DrvFs and 9p.

The LxUtil crate also implements the exact same API on Linux, just passing the file system
operations through to their respective Linux system calls. This allows you to write the same file
system code on Windows and Linux, using Linux semantics on both platforms as far as possible.
